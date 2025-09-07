
#![cfg_attr(not(any(feature = "export-abi", test)), no_main)]
extern crate alloc;
use alloc::{string::String, vec::Vec};

use stylus_sdk::{
    alloy_primitives::{Address, U256}, 
    prelude::*,
    alloy_sol_types::sol,
    evm,
};
sol! {
    error Unauthorized();
    error InvalidInput();
    error InsufficientFunds();
    error NotFound();
}

sol! {
    event ProviderRegistered(address indexed provider, string name);
    event PlanCreated(uint256 indexed planId, address indexed provider, uint256 price, uint256 interval);
    event SubscriptionCreated(uint256 indexed subscriptionId, address indexed user, uint256 indexed planId);
    event PaymentProcessed(address indexed from, address indexed to, uint256 amount, uint256 indexed subscriptionId);
    event ProviderEarnings(address indexed provider, uint256 indexed planId, uint256 amount);
    event EscrowDeposit(address indexed user, uint256 amount, uint256 newBalance);
    event EscrowWithdrawal(address indexed user, uint256 amount, uint256 newBalance);
}

#[derive(SolidityError)]
pub enum SubscriptionError {
    Unauthorized(Unauthorized),
    InvalidInput(InvalidInput),
    InsufficientFunds(InsufficientFunds),
    NotFound(NotFound),
}

sol_storage! {
    #[entrypoint]
    pub struct SubscriptionEscrow {
        address admin;
        uint256 protocol_fee_percentage;
        
        uint256 next_plan_id;
        uint256 next_subscription_id;
        
        mapping(address => bool) registered_providers;
        
        mapping(uint256 => address) plan_provider;
        mapping(uint256 => uint256) plan_price;
        mapping(uint256 => uint256) plan_interval;
        
        mapping(uint256 => uint256) subscription_plan_id;
        mapping(uint256 => address) subscription_subscriber;
        mapping(uint256 => uint256) subscription_last_payment;
        mapping(uint256 => bool) subscription_active;
        
        mapping(address => uint256) user_escrow_balance;
    }
}

#[public]
impl SubscriptionEscrow {
    
    pub fn initialize(&mut self) -> Result<bool, SubscriptionError> {
        if self.admin.get() != Address::ZERO {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let caller = self.vm().msg_sender();
        self.admin.set(caller);
        self.next_plan_id.set(U256::from(1));
        self.next_subscription_id.set(U256::from(1));
        self.protocol_fee_percentage.set(U256::from(250));
        
        Ok(true)
    }
    
    pub fn register_provider(&mut self, name: String) -> Result<bool, SubscriptionError> {
        let caller = self.vm().msg_sender();
        
        // Check if name is too long
        if name.len() > 100 {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        // Check if already registered
        if self.registered_providers.get(caller) {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        // Register the provider
        self.registered_providers.insert(caller, true);
        
        evm::log(ProviderRegistered { 
            provider: caller, 
            name: name 
        });
        
        Ok(true)
    }
    
    pub fn create_plan(&mut self, price: U256, interval: U256, _metadata_hash: String) -> Result<U256, SubscriptionError> {
        let caller = self.vm().msg_sender();
        self.require_registered_provider(caller)?;
        
        if price.is_zero() || interval.is_zero() {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let plan_id = self.next_plan_id.get();
        
        self.plan_provider.insert(plan_id, caller);
        self.plan_price.insert(plan_id, price);
        self.plan_interval.insert(plan_id, interval);
        
        self.next_plan_id.set(plan_id + U256::from(1));
        
        evm::log(PlanCreated {
            planId: plan_id,
            provider: caller,
            price: price,
            interval: interval
        });
        
        Ok(plan_id)
    }
    
    #[payable]
    pub fn subscribe(&mut self, plan_id: U256) -> Result<U256, SubscriptionError> {
        let caller = self.vm().msg_sender();
        let payment = self.vm().msg_value();
        
        let plan_provider = self.plan_provider.get(plan_id);
        if plan_provider == Address::ZERO {
            return Err(SubscriptionError::NotFound(NotFound {}));
        }
        
        let plan_price = self.plan_price.get(plan_id);
        
        if payment > U256::ZERO {
            let current_balance = self.user_escrow_balance.get(caller);
            self.user_escrow_balance.insert(caller, current_balance + payment);
        }
        
        let user_balance = self.user_escrow_balance.get(caller);
        if user_balance < plan_price {
            return Err(SubscriptionError::InsufficientFunds(InsufficientFunds {}));
        }
        
        let protocol_fee = (plan_price * self.protocol_fee_percentage.get()) / U256::from(10000);
        let provider_amount = plan_price - protocol_fee;
        
        let subscription_id = self.next_subscription_id.get();
        let current_time = U256::from(self.vm().block_timestamp());
        
        self.subscription_plan_id.insert(subscription_id, plan_id);
        self.subscription_subscriber.insert(subscription_id, caller);
        self.subscription_last_payment.insert(subscription_id, current_time);
        self.subscription_active.insert(subscription_id, true);
        
        self.user_escrow_balance.insert(caller, user_balance - plan_price);
        
        if let Err(_) = self.vm().transfer_eth(plan_provider, provider_amount) {
            self.user_escrow_balance.insert(caller, user_balance);
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        self.next_subscription_id.set(subscription_id + U256::from(1));
        
        evm::log(SubscriptionCreated {
            subscriptionId: subscription_id,
            user: caller,
            planId: plan_id
        });
        
        evm::log(PaymentProcessed {
            from: caller,
            to: plan_provider,
            amount: provider_amount,
            subscriptionId: subscription_id
        });
        
        evm::log(ProviderEarnings {
            provider: plan_provider,
            planId: plan_id,
            amount: provider_amount
        });
        
        Ok(subscription_id)
    }
    

    
    pub fn process_subscription_payment(&mut self, subscription_id: U256) -> Result<bool, SubscriptionError> {
        if !self.subscription_active.get(subscription_id) {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }

        let subscriber = self.subscription_subscriber.get(subscription_id);
        let plan_id = self.subscription_plan_id.get(subscription_id);
        let plan_provider = self.plan_provider.get(plan_id);
        let plan_price = self.plan_price.get(plan_id);
        let plan_interval = self.plan_interval.get(plan_id);
        let last_payment = self.subscription_last_payment.get(subscription_id);
        let current_time = U256::from(self.vm().block_timestamp());

        if current_time < last_payment + plan_interval {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }

        let user_balance = self.user_escrow_balance.get(subscriber);
        if user_balance < plan_price {
            self.subscription_active.insert(subscription_id, false);
            return Err(SubscriptionError::InsufficientFunds(InsufficientFunds {}));
        }

        let protocol_fee = (plan_price * self.protocol_fee_percentage.get()) / U256::from(10000);
        let provider_amount = plan_price - protocol_fee;

        self.user_escrow_balance.insert(subscriber, user_balance - plan_price);
        self.subscription_last_payment.insert(subscription_id, current_time);

        if let Err(_) = self.vm().transfer_eth(plan_provider, provider_amount) {
            self.user_escrow_balance.insert(subscriber, user_balance);
            self.subscription_last_payment.insert(subscription_id, last_payment);
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }

        evm::log(PaymentProcessed { 
            from: subscriber, 
            to: plan_provider, 
            amount: provider_amount,
            subscriptionId: subscription_id
        });
        
        evm::log(ProviderEarnings {
            provider: plan_provider,
            planId: plan_id,
            amount: provider_amount
        });

        Ok(true)
    }    pub fn get_user_balance(&self, user: Address) -> U256 {
        self.user_escrow_balance.get(user)
    }
    
    // Check if provider is registered
    pub fn is_provider_registered(&self, provider: Address) -> bool {
        self.registered_providers.get(provider)
    }
    

    // Get all available plans in one place (marketplace view)
    pub fn get_plans(&self) -> Vec<U256> {
        let max_plans = self.next_plan_id.get();
        let mut plan_ids = Vec::new();
        
        let mut plan_id = U256::from(1);
        while plan_id < max_plans && plan_ids.len() < 10 {
            let provider = self.plan_provider.get(plan_id);
            if provider != Address::ZERO {
                plan_ids.push(plan_id);
            }
            plan_id += U256::from(1);
        }
        plan_ids
    }

    // Deposit funds to escrow balance - HYBRID ESCROW FEATURE
    #[payable]
    pub fn deposit(&mut self) -> Result<bool, SubscriptionError> {
        let caller = self.vm().msg_sender();
        let payment = self.vm().msg_value();
        
        if payment.is_zero() {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let current_balance = self.user_escrow_balance.get(caller);
        let new_balance = current_balance + payment;
        
        self.user_escrow_balance.insert(caller, new_balance);
        
        evm::log(EscrowDeposit {
            user: caller,
            amount: payment,
            newBalance: new_balance
        });
        
        Ok(true)
    }

    // Withdraw balance
    pub fn withdraw(&mut self, amount: U256) -> Result<bool, SubscriptionError> {
        let caller = self.vm().msg_sender();
        let user_balance = self.user_escrow_balance.get(caller);
        
        if amount.is_zero() || user_balance < amount {
            return Err(SubscriptionError::InsufficientFunds(InsufficientFunds {}));
        }
        
        let new_balance = user_balance - amount;
        self.user_escrow_balance.insert(caller, new_balance);
        
        if let Err(_) = self.vm().transfer_eth(caller, amount) {
            self.user_escrow_balance.insert(caller, user_balance);
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        evm::log(EscrowWithdrawal {
            user: caller,
            amount: amount,
            newBalance: new_balance
        });
        
        Ok(true)
    }
    
    fn require_registered_provider(&self, provider: Address) -> Result<(), SubscriptionError> {
        if !self.registered_providers.get(provider) {
            return Err(SubscriptionError::Unauthorized(Unauthorized {}));
        }
        Ok(())
    }
}
