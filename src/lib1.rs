#![cfg_attr(not(any(feature = "export-abi", test)), no_main)]
extern crate alloc;
use alloc::{string::String, vec::Vec};

use stylus_sdk::{
    alloy_primitives::{Address, U256}, 
    prelude::*,
    alloy_sol_types::sol,
    evm,
    abi::Bytes,
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
    event PaymentProcessed(address indexed from, address indexed to, uint256 amount);
    event EarningsWithdrawn(address indexed provider, uint256 amount);
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
        uint256 total_value_locked;
        
        mapping(address => bool) registered_providers;
        mapping(address => uint256) provider_earnings;
        
        mapping(uint256 => address) plan_provider;
        mapping(uint256 => uint256) plan_price;
        mapping(uint256 => uint256) plan_interval;
        mapping(uint256 => bool) plan_active;
        
        mapping(uint256 => uint256) subscription_plan_id;
        mapping(uint256 => address) subscription_subscriber;
        mapping(uint256 => uint256) subscription_created_at;
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
        
        if self.registered_providers.get(caller) {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        if name.len() > 100 {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        self.registered_providers.insert(caller, true);
        self.provider_earnings.insert(caller, U256::ZERO);
        
        evm::log(ProviderRegistered { 
            provider: caller, 
            name: name 
        });
        
        Ok(true)
    }
    
    pub fn create_plan(&mut self, price: U256, interval: U256) -> Result<U256, SubscriptionError> {
        let caller = self.vm().msg_sender();
        self.require_registered_provider(caller)?;
        
        if price.is_zero() || interval.is_zero() {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let plan_id = self.next_plan_id.get();
        
        self.plan_provider.insert(plan_id, caller);
        self.plan_price.insert(plan_id, price);
        self.plan_interval.insert(plan_id, interval);
        self.plan_active.insert(plan_id, true);
        
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
        
        if !self.plan_active.get(plan_id) {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let plan_price = self.plan_price.get(plan_id);
        
        if payment > U256::ZERO {
            self.process_deposit(caller, payment)?;
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
        self.subscription_created_at.insert(subscription_id, current_time);
        self.subscription_last_payment.insert(subscription_id, current_time);
        self.subscription_active.insert(subscription_id, true);
        
        self.user_escrow_balance.insert(caller, user_balance - plan_price);
        
        let provider_earnings = self.provider_earnings.get(plan_provider);
        self.provider_earnings.insert(plan_provider, provider_earnings + provider_amount);
        
        self.next_subscription_id.set(subscription_id + U256::from(1));
        
        evm::log(SubscriptionCreated {
            subscriptionId: subscription_id,
            user: caller,
            planId: plan_id
        });
        
        evm::log(PaymentProcessed {
            from: caller,
            to: plan_provider,
            amount: provider_amount
        });
        
        Ok(subscription_id)
    }
    
    #[payable]
    pub fn deposit(&mut self) -> Result<bool, SubscriptionError> {
        let caller = self.vm().msg_sender();
        let amount = self.vm().msg_value();
        
        self.process_deposit(caller, amount)?;
        Ok(true)
    }
    
    pub fn withdraw_provider_earnings(&mut self) -> Result<bool, SubscriptionError> {
        let provider = self.vm().msg_sender();
        self.require_registered_provider(provider)?;
        
        let earnings = self.provider_earnings.get(provider);
        if earnings.is_zero() {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        self.provider_earnings.insert(provider, U256::ZERO);
        let total_locked = self.total_value_locked.get();
        self.total_value_locked.set(total_locked - earnings);
        
        match self.vm().transfer_eth(provider, earnings) {
            Ok(()) => {
                evm::log(EarningsWithdrawn { provider, amount: earnings });
                Ok(true)
            },
            Err(_) => {
                self.provider_earnings.insert(provider, earnings);
                self.total_value_locked.set(total_locked);
                Err(SubscriptionError::InvalidInput(InvalidInput {}))
            }
        }
    }
    
    pub fn checker(&self, subscriber: Address) -> (bool, Bytes) {
        let mut subscription_id = U256::from(1);
        let max_subscriptions = self.next_subscription_id.get();
        
        while subscription_id < max_subscriptions {
            if self.subscription_subscriber.get(subscription_id) == subscriber 
                && self.subscription_active.get(subscription_id) {
                
                let plan_id = self.subscription_plan_id.get(subscription_id);
                let plan_price = self.plan_price.get(plan_id);
                let plan_interval = self.plan_interval.get(plan_id);
                let last_payment = self.subscription_last_payment.get(subscription_id);
                let user_balance = self.user_escrow_balance.get(subscriber);
                let current_time = U256::from(self.vm().block_timestamp());
                
                if current_time >= last_payment + plan_interval && user_balance >= plan_price {
                    let mut exec_payload = Vec::new();
                    exec_payload.extend_from_slice(&[0x98, 0x75, 0xc6, 0x9a]);
                    let id_bytes = subscription_id.to_be_bytes::<32>();
                    exec_payload.extend_from_slice(&id_bytes);
                    return (true, Bytes::from(exec_payload));
                }
            }
            subscription_id += U256::from(1);
        }
        
        (false, Bytes::from(Vec::<u8>::new()))
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
        let provider_earnings = self.provider_earnings.get(plan_provider);
        self.provider_earnings.insert(plan_provider, provider_earnings + provider_amount);
        self.subscription_last_payment.insert(subscription_id, current_time);

        evm::log(PaymentProcessed { from: subscriber, to: plan_provider, amount: provider_amount });
        Ok(true)
    }    pub fn get_admin(&self) -> Address {
        self.admin.get()
    }
    
    pub fn get_user_balance(&self, user: Address) -> U256 {
        self.user_escrow_balance.get(user)
    }
    
    pub fn get_provider_earnings(&self, provider: Address) -> U256 {
        self.provider_earnings.get(provider)
    }
    
    pub fn is_provider_registered(&self, provider: Address) -> bool {
        self.registered_providers.get(provider)
    }
    
    fn require_registered_provider(&self, provider: Address) -> Result<(), SubscriptionError> {
        if !self.registered_providers.get(provider) {
            return Err(SubscriptionError::Unauthorized(Unauthorized {}));
        }
        Ok(())
    }
    
    fn process_deposit(&mut self, user: Address, amount: U256) -> Result<(), SubscriptionError> {
        if amount.is_zero() {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        let current_balance = self.user_escrow_balance.get(user);
        self.user_escrow_balance.insert(user, current_balance + amount);
        
        // Update contract TVL
        let total_locked = self.total_value_locked.get();
        self.total_value_locked.set(total_locked + amount);
        
        Ok(())
    }
}
