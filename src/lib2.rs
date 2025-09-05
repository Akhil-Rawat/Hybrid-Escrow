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
        
        if self.registered_providers.get(caller) {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        if name.len() > 100 {
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }
        
        self.registered_providers.insert(caller, true);
        
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
        self.subscription_last_payment.insert(subscription_id, current_time);
        self.subscription_active.insert(subscription_id, true);
        
        self.user_escrow_balance.insert(caller, user_balance - plan_price);
        
        // Direct transfer to provider (immediate payment on subscription)
        if let Err(_) = self.vm().transfer_eth(plan_provider, provider_amount) {
            // Revert subscription creation if transfer fails
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
            amount: provider_amount
        });
        
        Ok(subscription_id)
    }
    
    pub fn checker(&self) -> (bool, Bytes) {
        let mut subscription_id = U256::from(1);
        let max_subscriptions = self.next_subscription_id.get();
        
        while subscription_id < max_subscriptions {
            if self.subscription_active.get(subscription_id) {
                
                let subscriber = self.subscription_subscriber.get(subscription_id);
                let plan_id = self.subscription_plan_id.get(subscription_id);
                let plan_price = self.plan_price.get(plan_id);
                let plan_interval = self.plan_interval.get(plan_id);
                let last_payment = self.subscription_last_payment.get(subscription_id);
                let user_balance = self.user_escrow_balance.get(subscriber);
                let current_time = U256::from(self.vm().block_timestamp());
                
                if current_time >= last_payment + plan_interval && user_balance >= plan_price {
                    // Create properly ABI-encoded calldata for processSubscriptionPayment(uint256)
                    let mut exec_payload = Vec::with_capacity(36);
                    
                    // Function selector for processSubscriptionPayment(uint256): 0x9875c69a
                    exec_payload.extend_from_slice(&[0x98, 0x75, 0xc6, 0x9a]);
                    
                    // ABI encode subscription_id as uint256 (32 bytes, big-endian)
                    let id_bytes = subscription_id.to_be_bytes::<32>();
                    exec_payload.extend_from_slice(&id_bytes);
                    
                    return (true, Bytes::from(exec_payload));
                }
            }
            subscription_id += U256::from(1);
        }
        
        // Return false with empty bytes when no payments are due
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

        // Deduct from user escrow balance
        self.user_escrow_balance.insert(subscriber, user_balance - plan_price);
        
        // Update payment tracking
        self.subscription_last_payment.insert(subscription_id, current_time);

        // DIRECT TRANSFER: Send payment directly to provider wallet (like hybrid contract)
        if let Err(_) = self.vm().transfer_eth(plan_provider, provider_amount) {
            // Revert changes if transfer fails
            self.user_escrow_balance.insert(subscriber, user_balance);
            self.subscription_last_payment.insert(subscription_id, last_payment);
            return Err(SubscriptionError::InvalidInput(InvalidInput {}));
        }

        evm::log(PaymentProcessed { from: subscriber, to: plan_provider, amount: provider_amount });
        Ok(true)
    }    pub fn get_admin(&self) -> Address {
        self.admin.get()
    }
    
    pub fn get_user_balance(&self, user: Address) -> U256 {
        self.user_escrow_balance.get(user)
    }
    
    pub fn is_provider_registered(&self, provider: Address) -> bool {
        self.registered_providers.get(provider)
    }

    // Get total number of active subscriptions
    pub fn get_active_subscription_count(&self) -> U256 {
        let mut count = 0u64;
        let max_subscriptions = self.next_subscription_id.get();
        let mut subscription_id = U256::from(1);
        
        while subscription_id < max_subscriptions {
            if self.subscription_active.get(subscription_id) {
                count += 1;
            }
            subscription_id += U256::from(1);
        }
        U256::from(count)
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
        
        Ok(())
    }
}
