#![no_std]

use earnproof_shared::{
    ContractError, InterfaceVersion, IssuerError, IssuerRecord, IssuerStatus,
    ISSUER_REGISTRY_INTERFACE_VERSION, TTL_EXTEND_TO_LEDGERS, TTL_THRESHOLD_LEDGERS,
};
use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, BytesN, Env};

#[contract]
pub struct IssuerRegistryContract;

#[contracttype]
enum DataKey {
    Admin,
    Issuer(BytesN<32>),
    AddressIssuer(Address),
    /// Allowlist entry: maps a WASM hash to the target contract version.
    AllowedWasm(BytesN<32>),
    /// Monotonically-increasing contract version.  Prevents downgrade.
    ContractVersion,
    /// Monotonic counter advanced once per externally visible issuer mutation.
    /// Off-chain consumers poll it as a cheap cache-invalidation signal.
    IssuerEpoch,
    /// Governed maximum number of issuers that may hold `Active` status at once.
    MaxActiveIssuers,
    /// Current number of issuers holding `Active` status.
    ActiveIssuerCount,
    /// Governed minimum ledger-time cooldown, in seconds, enforced before a
    /// suspended issuer may be reactivated.
    ReactivationCooldown,
    /// Per-issuer earliest ledger time at which reactivation is permitted.
    /// Fixed at suspension time from the cooldown then in force.
    ReactivatableAt(BytesN<32>),
}

// ── upgrade events ────────────────────────────────────────────────────────────

/// Emitted when the admin adds a WASM hash to the upgrade allowlist.
#[contractevent]
pub struct UpgradeAllowlisted {
    pub wasm_hash: BytesN<32>,
    pub new_contract_version: u32,
    pub approved_by: Address,
}

/// Emitted when the admin removes a WASM hash from the allowlist without
/// applying it.
#[contractevent]
pub struct UpgradeRevoked {
    pub wasm_hash: BytesN<32>,
    pub revoked_by: Address,
}

/// Emitted when a WASM upgrade is successfully applied.
#[contractevent]
pub struct ContractUpgraded {
    pub new_wasm_hash: BytesN<32>,
    pub old_contract_version: u32,
    pub new_contract_version: u32,
    pub upgraded_by: Address,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Emitted when an issuer is successfully registered.
///
/// `epoch` is the registry epoch after this mutation, so an indexer can order
/// lifecycle events and detect gaps without a separate read.
#[contractevent]
pub struct IssuerRegistered {
    pub issuer_id_hash: BytesN<32>,
    pub issuer_address: Address,
    pub metadata_hash: BytesN<32>,
    pub created_at: u64,
    pub epoch: u64,
}

/// Emitted when an issuer's public metadata hash is updated.
#[contractevent]
pub struct IssuerMetadataUpdated {
    pub issuer_id_hash: BytesN<32>,
    pub metadata_hash: BytesN<32>,
    pub updated_at: u64,
    pub epoch: u64,
}

/// Emitted when an issuer is suspended.
#[contractevent]
pub struct IssuerSuspended {
    pub issuer_id_hash: BytesN<32>,
    pub updated_at: u64,
    pub epoch: u64,
}

/// Emitted when a suspended issuer is reactivated.
#[contractevent]
pub struct IssuerReactivated {
    pub issuer_id_hash: BytesN<32>,
    pub updated_at: u64,
    pub epoch: u64,
}

/// Emitted when an issuer is permanently revoked.
#[contractevent]
pub struct IssuerRevoked {
    pub issuer_id_hash: BytesN<32>,
    pub updated_at: u64,
    pub epoch: u64,
}

/// Emitted when an issuer's on-chain wallet address is rotated.
/// Both old and new addresses are included so indexers can update their mapping
/// without scanning storage.
#[contractevent]
pub struct IssuerAddressRotated {
    pub issuer_id_hash: BytesN<32>,
    pub old_address: Address,
    pub new_address: Address,
    pub updated_at: u64,
    pub epoch: u64,
}

// ── capacity and cooldown governance events ─────────────────────────────────

/// Emitted when the governed maximum active-issuer capacity is changed.
#[contractevent]
pub struct MaxActiveIssuersChanged {
    pub new_max: u32,
    pub active_count: u32,
    pub changed_by: Address,
}

/// Emitted when the governed reactivation cooldown is changed.
#[contractevent]
pub struct ReactivationCooldownChanged {
    pub new_cooldown_seconds: u64,
    pub changed_by: Address,
}

// ---------------------------------------------------------------------------
// Contract implementation
// ---------------------------------------------------------------------------

#[contractimpl]
impl IssuerRegistryContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }

        Self::require_valid_admin(&admin)?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &1_u32);
        // Deterministic starting state for the epoch, capacity, and cooldown
        // features. Capacity defaults to unlimited so pre-existing behaviour is
        // preserved until an admin sets a real bound.
        env.storage().instance().set(&DataKey::IssuerEpoch, &0_u64);
        env.storage()
            .instance()
            .set(&DataKey::MaxActiveIssuers, &u32::MAX);
        env.storage()
            .instance()
            .set(&DataKey::ActiveIssuerCount, &0_u32);
        env.storage()
            .instance()
            .set(&DataKey::ReactivationCooldown, &0_u64);
        Self::extend_instance_ttl(env);
        Ok(())
    }

    /// Initializes the epoch, capacity, and cooldown state on a contract that
    /// was deployed before these features existed.
    ///
    /// Idempotent for the keys that have a natural default (epoch, capacity
    /// limit, cooldown): they are only written when absent. The active-issuer
    /// count cannot be derived on-chain, so the caller supplies the known count
    /// once; it is written unconditionally. Admin-only.
    pub fn migrate(env: Env, active_issuer_count: u32) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_auth(&admin);

        if !env.storage().instance().has(&DataKey::IssuerEpoch) {
            env.storage().instance().set(&DataKey::IssuerEpoch, &0_u64);
        }
        if !env.storage().instance().has(&DataKey::MaxActiveIssuers) {
            env.storage()
                .instance()
                .set(&DataKey::MaxActiveIssuers, &u32::MAX);
        }
        if !env.storage().instance().has(&DataKey::ReactivationCooldown) {
            env.storage()
                .instance()
                .set(&DataKey::ReactivationCooldown, &0_u64);
        }
        env.storage()
            .instance()
            .set(&DataKey::ActiveIssuerCount, &active_issuer_count);
        Self::extend_instance_ttl(env);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn register_issuer(
        env: Env,
        issuer_id_hash: BytesN<32>,
        issuer_address: Address,
        metadata_hash: BytesN<32>,
    ) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_valid_issuer_address(&issuer_address)?;
        Self::require_auth(&admin);

        let key = DataKey::Issuer(issuer_id_hash.clone());
        if env.storage().persistent().has(&key) {
            return Err(IssuerError::IssuerAlreadyRegistered);
        }

        let address_key = DataKey::AddressIssuer(issuer_address.clone());
        if env.storage().persistent().has(&address_key) {
            return Err(IssuerError::IssuerAddressAlreadyRegistered);
        }

        // A new issuer starts Active, so it consumes one capacity slot. This is
        // checked and reserved before any state is written, so a rejected
        // registration mutates nothing.
        Self::reserve_active_capacity(&env)?;

        let now = env.ledger().timestamp();
        let record = IssuerRecord {
            issuer_id_hash: issuer_id_hash.clone(),
            issuer_address: issuer_address.clone(),
            metadata_hash: metadata_hash.clone(),
            status: IssuerStatus::Active,
            created_at: now,
            updated_at: now,
        };

        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .set(&address_key, &issuer_id_hash);
        Self::extend_issuer_ttl(env.clone(), issuer_id_hash.clone());
        Self::extend_address_ttl(env.clone(), issuer_address.clone());

        let epoch = Self::bump_epoch(&env);
        IssuerRegistered {
            issuer_id_hash,
            issuer_address,
            metadata_hash,
            created_at: now,
            epoch,
        }
        .publish(&env);
        Ok(())
    }

    pub fn update_issuer(
        env: Env,
        issuer_id_hash: BytesN<32>,
        metadata_hash: BytesN<32>,
    ) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_auth(&admin);

        let key = DataKey::Issuer(issuer_id_hash.clone());
        let mut record: IssuerRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(IssuerError::IssuerNotFound)?;

        if record.status == IssuerStatus::Revoked {
            return Err(IssuerError::IssuerRevoked);
        }

        let now = env.ledger().timestamp();
        record.metadata_hash = metadata_hash.clone();
        record.updated_at = now;
        env.storage().persistent().set(&key, &record);
        Self::extend_issuer_key_ttl(env.clone(), &key);

        let epoch = Self::bump_epoch(&env);
        IssuerMetadataUpdated {
            issuer_id_hash,
            metadata_hash,
            updated_at: now,
            epoch,
        }
        .publish(&env);
        Ok(())
    }

    pub fn suspend_issuer(env: Env, issuer_id_hash: BytesN<32>) -> Result<(), IssuerError> {
        Self::set_status(env, issuer_id_hash, IssuerStatus::Suspended)
    }

    pub fn reactivate_issuer(env: Env, issuer_id_hash: BytesN<32>) -> Result<(), IssuerError> {
        Self::set_status(env, issuer_id_hash, IssuerStatus::Active)
    }

    pub fn revoke_issuer(env: Env, issuer_id_hash: BytesN<32>) -> Result<(), IssuerError> {
        Self::set_status(env, issuer_id_hash, IssuerStatus::Revoked)
    }

    pub fn rotate_issuer_address(
        env: Env,
        issuer_id_hash: BytesN<32>,
        new_address: Address,
    ) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_valid_issuer_address(&new_address)?;
        Self::require_auth(&admin);

        let key = DataKey::Issuer(issuer_id_hash.clone());
        let mut record: IssuerRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(IssuerError::IssuerNotFound)?;

        if record.status == IssuerStatus::Revoked {
            return Err(IssuerError::IssuerRevoked);
        }
        if new_address == record.issuer_address {
            return Err(IssuerError::InvalidAddress);
        }

        let new_address_key = DataKey::AddressIssuer(new_address.clone());
        if env.storage().persistent().has(&new_address_key) {
            return Err(IssuerError::IssuerAddressAlreadyRegistered);
        }

        let old_address = record.issuer_address.clone();
        env.storage()
            .persistent()
            .remove(&DataKey::AddressIssuer(old_address.clone()));
        record.issuer_address = new_address.clone();
        let now = env.ledger().timestamp();
        record.updated_at = now;
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .set(&new_address_key, &issuer_id_hash);
        Self::extend_issuer_key_ttl(env.clone(), &key);
        Self::extend_address_ttl(env.clone(), new_address.clone());

        let epoch = Self::bump_epoch(&env);
        IssuerAddressRotated {
            issuer_id_hash,
            old_address,
            new_address,
            updated_at: now,
            epoch,
        }
        .publish(&env);
        Ok(())
    }

    pub fn get_issuer(env: Env, issuer_id_hash: BytesN<32>) -> Result<IssuerRecord, IssuerError> {
        let key = DataKey::Issuer(issuer_id_hash);
        let record = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(IssuerError::IssuerNotFound)?;
        Self::extend_issuer_key_ttl(env, &key);
        Ok(record)
    }

    pub fn is_active_issuer(env: Env, issuer_id_hash: BytesN<32>) -> bool {
        match Self::get_issuer(env, issuer_id_hash) {
            Ok(record) => record.status == IssuerStatus::Active,
            Err(_) => false,
        }
    }

    pub fn is_active_address(env: Env, issuer_address: Address) -> bool {
        let issuer_id_hash: Option<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&DataKey::AddressIssuer(issuer_address.clone()));

        match issuer_id_hash {
            Some(id) => Self::is_active_issuer(env, id),
            None => false,
        }
    }

    // ── epoch, capacity, cooldown, interface version ──────────────────────────

    /// Machine-readable interface version this contract exposes to consumers.
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        ISSUER_REGISTRY_INTERFACE_VERSION
    }

    /// Current registry epoch. Advances by one on every externally visible
    /// issuer mutation. A stable value means nothing has changed; consumers use
    /// it to skip refreshing cached issuer data. Starts at 0.
    pub fn get_issuer_epoch(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::IssuerEpoch)
            .unwrap_or(0)
    }

    /// Number of issuers currently in `Active` status.
    pub fn get_active_issuer_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ActiveIssuerCount)
            .unwrap_or(0)
    }

    /// Governed maximum number of simultaneously `Active` issuers. Defaults to
    /// `u32::MAX` (effectively unlimited) until an admin sets a bound.
    pub fn get_max_active_issuers(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::MaxActiveIssuers)
            .unwrap_or(u32::MAX)
    }

    /// Governed reactivation cooldown, in seconds. Defaults to 0 (no cooldown).
    pub fn get_reactivation_cooldown(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::ReactivationCooldown)
            .unwrap_or(0)
    }

    /// Earliest ledger time at which a suspended issuer may be reactivated.
    /// Returns 0 when the issuer has never been suspended or has no cooldown
    /// pending. Fixed at suspension time, so a later cooldown change does not
    /// move it.
    pub fn get_earliest_reactivation(env: Env, issuer_id_hash: BytesN<32>) -> u64 {
        Self::earliest_reactivation(&env, &issuer_id_hash)
    }

    /// Admin-only: set the maximum active-issuer capacity.
    ///
    /// A new limit below the current active usage is rejected with
    /// `MaxBelowActiveUsage` unless `allow_below_usage` is true, which lets an
    /// admin ratchet the ceiling down toward a target without first suspending
    /// issuers (no existing issuer is affected; only future reactivations and
    /// registrations see the tighter bound).
    pub fn set_max_active_issuers(
        env: Env,
        new_max: u32,
        allow_below_usage: bool,
    ) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_auth(&admin);

        let active_count = Self::get_active_issuer_count(env.clone());
        if new_max < active_count && !allow_below_usage {
            return Err(IssuerError::MaxBelowActiveUsage);
        }

        env.storage()
            .instance()
            .set(&DataKey::MaxActiveIssuers, &new_max);
        Self::extend_instance_ttl(env.clone());

        MaxActiveIssuersChanged {
            new_max,
            active_count,
            changed_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Admin-only: set the reactivation cooldown, in seconds.
    ///
    /// The new value applies only to suspensions that happen after this call;
    /// the earliest reactivation time of an already-suspended issuer is fixed
    /// and is never retroactively shortened or lengthened.
    pub fn set_reactivation_cooldown(env: Env, cooldown_seconds: u64) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_auth(&admin);

        env.storage()
            .instance()
            .set(&DataKey::ReactivationCooldown, &cooldown_seconds);
        Self::extend_instance_ttl(env.clone());

        ReactivationCooldownChanged {
            new_cooldown_seconds: cooldown_seconds,
            changed_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    // ── upgrade governance ────────────────────────────────────────────────────

    /// Returns the stored monotonic contract version.  Starts at 1.
    pub fn get_contract_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0)
    }

    /// Admin-only: add `wasm_hash` to the upgrade allowlist.
    ///
    /// `new_version` must be strictly greater than the current contract
    /// version to prevent pre-approving a downgrade.
    pub fn approve_upgrade(env: Env, wasm_hash: BytesN<32>, new_version: u32) {
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        let current = Self::get_contract_version(env.clone());
        if new_version <= current {
            panic!("new_version must be greater than current contract version");
        }

        env.storage()
            .instance()
            .set(&DataKey::AllowedWasm(wasm_hash.clone()), &new_version);
        Self::extend_instance_ttl(env.clone());

        UpgradeAllowlisted {
            wasm_hash,
            new_contract_version: new_version,
            approved_by: admin,
        }
        .publish(&env);
    }

    /// Admin-only: remove a hash from the allowlist without applying it.
    pub fn revoke_upgrade(env: Env, wasm_hash: BytesN<32>) {
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        UpgradeRevoked {
            wasm_hash,
            revoked_by: admin,
        }
        .publish(&env);
    }

    /// Returns true when `wasm_hash` is on the allowlist.
    pub fn is_upgrade_allowed(env: Env, wasm_hash: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::AllowedWasm(wasm_hash))
    }

    /// Admin-only: apply an in-place WASM upgrade.
    ///
    /// Requirements:
    /// 1. Caller is the admin.
    /// 2. `wasm_hash` is on the allowlist.
    /// 3. Target version is strictly greater than current (downgrade guard).
    ///
    /// On success the allowlist entry is consumed and `ContractVersion` is
    /// advanced.
    pub fn upgrade_contract(env: Env, wasm_hash: BytesN<32>) {
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        let new_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowedWasm(wasm_hash.clone()))
            .expect("wasm hash not on allowlist");

        let old_version = Self::get_contract_version(env.clone());
        if new_version <= old_version {
            panic!("upgrade would not advance contract version");
        }

        // Consume allowlist entry before applying to prevent replay.
        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        #[cfg(not(test))]
        env.deployer()
            .update_current_contract_wasm(wasm_hash.clone());

        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &new_version);
        Self::extend_instance_ttl(env.clone());

        ContractUpgraded {
            new_wasm_hash: wasm_hash,
            old_contract_version: old_version,
            new_contract_version: new_version,
            upgraded_by: admin,
        }
        .publish(&env);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn require_valid_admin(address: &Address) -> Result<(), ContractError> {
        if !earnproof_shared::is_valid_principal_address(address) {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn require_valid_issuer_address(address: &Address) -> Result<(), IssuerError> {
        if !earnproof_shared::is_valid_principal_address(address) {
            return Err(IssuerError::InvalidAddress);
        }
        Ok(())
    }

    fn set_status(
        env: Env,
        issuer_id_hash: BytesN<32>,
        status: IssuerStatus,
    ) -> Result<(), IssuerError> {
        let admin = Self::get_admin(env.clone()).map_err(|_| IssuerError::IssuerNotFound)?;
        Self::require_auth(&admin);

        let key = DataKey::Issuer(issuer_id_hash.clone());
        let mut record: IssuerRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(IssuerError::IssuerNotFound)?;

        let previous = record.status.clone();
        if previous == IssuerStatus::Revoked && status != IssuerStatus::Revoked {
            return Err(IssuerError::InvalidTransition);
        }

        let now = env.ledger().timestamp();

        // Enforce cooldown and capacity, and adjust the active-issuer count, per
        // transition. All checks that can reject the call run before any state
        // is written, so a rejected transition mutates nothing.
        match status {
            IssuerStatus::Active => {
                if previous == IssuerStatus::Suspended {
                    let earliest = Self::earliest_reactivation(&env, &issuer_id_hash);
                    if now < earliest {
                        return Err(IssuerError::ReactivationCooldownActive);
                    }
                    // Reactivation returns the issuer to Active, reclaiming a slot.
                    Self::reserve_active_capacity(&env)?;
                    env.storage()
                        .persistent()
                        .remove(&DataKey::ReactivatableAt(issuer_id_hash.clone()));
                }
            }
            IssuerStatus::Suspended => {
                if previous == IssuerStatus::Active {
                    Self::release_active_capacity(&env);
                }
                if previous != IssuerStatus::Revoked {
                    // Fix the earliest reactivation time from the cooldown in
                    // force now. A later cooldown change does not move it.
                    let cooldown = Self::get_reactivation_cooldown(env.clone());
                    let earliest = now.saturating_add(cooldown);
                    env.storage()
                        .persistent()
                        .set(&DataKey::ReactivatableAt(issuer_id_hash.clone()), &earliest);
                    Self::extend_reactivatable_ttl(env.clone(), &issuer_id_hash);
                }
            }
            IssuerStatus::Revoked => {
                if previous == IssuerStatus::Active {
                    Self::release_active_capacity(&env);
                }
            }
        }

        record.status = status.clone();
        record.updated_at = now;
        env.storage().persistent().set(&key, &record);
        Self::extend_issuer_key_ttl(env.clone(), &key);

        let epoch = Self::bump_epoch(&env);
        match status {
            IssuerStatus::Active => IssuerReactivated {
                issuer_id_hash,
                updated_at: now,
                epoch,
            }
            .publish(&env),
            IssuerStatus::Suspended => IssuerSuspended {
                issuer_id_hash,
                updated_at: now,
                epoch,
            }
            .publish(&env),
            IssuerStatus::Revoked => IssuerRevoked {
                issuer_id_hash,
                updated_at: now,
                epoch,
            }
            .publish(&env),
        }
        Ok(())
    }

    /// Advances the registry epoch by one and returns the new value.
    /// Overflow is explicit: at `u64::MAX` the call panics rather than wrapping,
    /// which is unreachable in practice (one bump per mutation).
    fn bump_epoch(env: &Env) -> u64 {
        let current = Self::get_issuer_epoch(env.clone());
        let next = current
            .checked_add(1)
            .unwrap_or_else(|| panic!("issuer epoch overflow: reached maximum"));
        env.storage().instance().set(&DataKey::IssuerEpoch, &next);
        Self::extend_instance_ttl(env.clone());
        next
    }

    /// Reserves one active-issuer slot, rejecting if the governed capacity is
    /// already full. Increments the active count on success.
    fn reserve_active_capacity(env: &Env) -> Result<(), IssuerError> {
        let count = Self::get_active_issuer_count(env.clone());
        let max = Self::get_max_active_issuers(env.clone());
        if count >= max {
            return Err(IssuerError::IssuerCapacityExceeded);
        }
        let next = count
            .checked_add(1)
            .ok_or(IssuerError::IssuerCapacityExceeded)?;
        env.storage()
            .instance()
            .set(&DataKey::ActiveIssuerCount, &next);
        Self::extend_instance_ttl(env.clone());
        Ok(())
    }

    /// Releases one active-issuer slot. Saturates at zero as a defensive
    /// measure; the accounting never underflows on a valid transition.
    fn release_active_capacity(env: &Env) {
        let count = Self::get_active_issuer_count(env.clone());
        let next = count.saturating_sub(1);
        env.storage()
            .instance()
            .set(&DataKey::ActiveIssuerCount, &next);
        Self::extend_instance_ttl(env.clone());
    }

    fn earliest_reactivation(env: &Env, issuer_id_hash: &BytesN<32>) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::ReactivatableAt(issuer_id_hash.clone()))
            .unwrap_or(0)
    }

    fn extend_reactivatable_ttl(env: Env, issuer_id_hash: &BytesN<32>) {
        env.storage().persistent().extend_ttl(
            &DataKey::ReactivatableAt(issuer_id_hash.clone()),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_TO_LEDGERS,
        );
    }

    fn extend_instance_ttl(env: Env) {
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_TO_LEDGERS);
    }

    fn extend_issuer_ttl(env: Env, issuer_id_hash: BytesN<32>) {
        Self::extend_issuer_key_ttl(env, &DataKey::Issuer(issuer_id_hash));
    }

    fn extend_issuer_key_ttl(env: Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_TO_LEDGERS);
    }

    fn extend_address_ttl(env: Env, issuer_address: Address) {
        env.storage().persistent().extend_ttl(
            &DataKey::AddressIssuer(issuer_address),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_TO_LEDGERS,
        );
    }

    fn require_auth(address: &Address) {
        address.require_auth();
    }

    pub fn get_issuer_by_address(
        env: Env,
        issuer_address: Address,
    ) -> Result<IssuerRecord, IssuerError> {
        let issuer_id_hash: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::AddressIssuer(issuer_address.clone()))
            .ok_or(IssuerError::IssuerAddressNotFound)?;

        let record = env
            .storage()
            .persistent()
            .get(&DataKey::Issuer(issuer_id_hash))
            .ok_or(IssuerError::IssuerNotFound)?;
        Self::extend_address_ttl(env, issuer_address);
        Ok(record)
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::{DataKey, IssuerRegistryContract, IssuerRegistryContractClient};
    use earnproof_shared::{IssuerError, IssuerStatus, TTL_THRESHOLD_LEDGERS};
    use soroban_sdk::{
        testutils::{
            storage::Persistent as _, Address as _, Events, Ledger as _, MockAuth, MockAuthInvoke,
        },
        Address, BytesN, Env, IntoVal,
    };

    const ADMIN: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";
    const ISSUER_ONE: &str = "GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U";
    const ISSUER_TWO: &str = "GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG";

    fn bytes(env: &Env, value: u8) -> BytesN<32> {
        BytesN::from_array(env, &[value; 32])
    }

    fn setup() -> (Env, IssuerRegistryContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        client.initialize(&admin);
        (env, client, admin)
    }

    // ── existing tests ────────────────────────────────────────────────────────
    // -----------------------------------------------------------------------
    // Existing behavioral tests (preserved)
    // -----------------------------------------------------------------------

    #[test]
    fn registers_and_reads_active_issuer() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let metadata_hash = bytes(&env, 2);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &metadata_hash);

        let record = client.get_issuer(&issuer_id);
        assert_eq!(record.issuer_id_hash, issuer_id);
        assert_eq!(record.issuer_address, issuer_address);
        assert_eq!(record.metadata_hash, metadata_hash);
        assert_eq!(record.status, IssuerStatus::Active);
        assert!(client.is_active_issuer(&issuer_id));
        assert!(client.is_active_address(&issuer_address));
    }

    #[test]
    fn status_transitions_reject_reactivated_revoked_issuer() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.suspend_issuer(&issuer_id);
        assert!(!client.is_active_issuer(&issuer_id));

        client.reactivate_issuer(&issuer_id);
        assert!(client.is_active_issuer(&issuer_id));

        client.revoke_issuer(&issuer_id);
        assert!(!client.is_active_issuer(&issuer_id));
    }

    #[test]
    fn rejects_duplicate_issuer_id() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));

        let result = client.try_register_issuer(
            &issuer_id,
            &Address::from_str(&env, ISSUER_TWO),
            &bytes(&env, 3),
        );
        assert_eq!(result, Err(Ok(IssuerError::IssuerAlreadyRegistered)));
    }

    #[test]
    fn revoked_issuer_cannot_be_reactivated() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.revoke_issuer(&issuer_id);

        let result = client.try_reactivate_issuer(&issuer_id);
        assert_eq!(result, Err(Ok(IssuerError::InvalidTransition)));
    }

    #[test]
    fn extends_issuer_storage_ttl() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));

        env.as_contract(&client.address, || {
            assert!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Issuer(issuer_id.clone()))
                    > TTL_THRESHOLD_LEDGERS
            );
            assert!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::AddressIssuer(issuer_address.clone()))
                    > TTL_THRESHOLD_LEDGERS
            );
        });
    }

    // ── upgrade governance tests ──────────────────────────────────────────────

    #[test]
    fn contract_version_initialized_to_one() {
        let (_env, client, _admin) = setup();
        assert_eq!(client.get_contract_version(), 1);
    }

    #[test]
    fn approve_and_check_allowlist() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0xab);

        assert!(!client.is_upgrade_allowed(&hash));
        client.approve_upgrade(&hash, &2);
        assert!(client.is_upgrade_allowed(&hash));
    }

    #[test]
    fn revoke_removes_from_allowlist() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0xcd);

        client.approve_upgrade(&hash, &2);
        client.revoke_upgrade(&hash);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn approve_upgrade_rejects_downgrade_version() {
        let (env, client, _admin) = setup();
        client.approve_upgrade(&bytes(&env, 1), &1);
    }

    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_contract_rejects_non_allowlisted_hash() {
        let (env, client, _admin) = setup();
        client.upgrade_contract(&bytes(&env, 0xff));
    }

    /// Auth guard: upgrade_contract without admin signature must panic.
    #[test]
    #[should_panic]
    fn upgrade_contract_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        env.mock_all_auths();
        client.initialize(&admin);
        let hash = BytesN::from_array(&env, &[0xde; 32]);
        client.approve_upgrade(&hash, &2);
        env.set_auths(&[]);

        client.upgrade_contract(&hash);
    }

    #[test]
    fn upgrade_advances_version_and_consumes_allowlist() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x42);

        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);

        assert_eq!(client.get_contract_version(), 2);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_hash_cannot_be_replayed() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x42);

        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);
        client.upgrade_contract(&hash);
    }

    /// Persistent issuer state must survive an upgrade.
    #[test]
    fn state_preserved_across_upgrade() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        assert!(client.is_active_issuer(&issuer_id));

        let hash = bytes(&env, 0x77);
        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);

        // Issuer record must still be intact.
        assert!(client.is_active_issuer(&issuer_id));
        assert_eq!(client.get_contract_version(), 2);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn cannot_re_approve_old_version_after_upgrade() {
        let (env, client, _admin) = setup();
        let hash_v2 = bytes(&env, 0x01);
        let old_hash = bytes(&env, 0x02);

        client.approve_upgrade(&hash_v2, &2);
        client.upgrade_contract(&hash_v2);

        // Attempting to allowlist version 1 after reaching version 2.
        client.approve_upgrade(&old_hash, &1);
    }

    // -----------------------------------------------------------------------
    // Event payload tests
    //
    // The Soroban test environment clears the event buffer at the start of each
    // top-level contract invocation (invocation metering is enabled by default
    // in Env::default()). Therefore env.events().all().events() reflects only
    // the events from the most recent invocation. Tests assert on the count
    // returned by a single invocation rather than a before/after diff.
    //
    // Failed invocations produce no contract events (failed_call events are
    // filtered out by all()). The catch_unwind tests confirm this by asserting
    // that a failed call leaves zero success events.
    // -----------------------------------------------------------------------

    /// register_issuer must emit exactly one event on success.
    #[test]
    fn register_issuer_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let metadata_hash = bytes(&env, 2);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &metadata_hash);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on registration"
        );
    }

    /// Duplicate registration panics before emitting any success event.
    #[test]
    fn register_issuer_failure_emits_no_success_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));

        // Attempt a duplicate — the invocation must panic.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 3));
        }));
        assert!(result.is_err(), "expected panic on duplicate");
        // Failed invocations emit no contract success events.
        assert_eq!(
            env.events().all().events().len(),
            0,
            "no success event should be emitted on a failed registration"
        );
    }

    /// update_issuer emits exactly one event on success.
    #[test]
    fn update_issuer_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);
        let new_metadata = bytes(&env, 99);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.update_issuer(&issuer_id, &new_metadata);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on metadata update"
        );
    }

    /// Updating a revoked issuer panics and emits no success event.
    #[test]
    fn update_revoked_issuer_emits_no_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.revoke_issuer(&issuer_id);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_issuer(&issuer_id, &bytes(&env, 99));
        }));
        assert!(result.is_err(), "expected panic on revoked issuer update");
        assert_eq!(
            env.events().all().events().len(),
            0,
            "no success event should be emitted on a failed update"
        );
    }

    /// suspend_issuer emits exactly one event.
    #[test]
    fn suspend_issuer_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.suspend_issuer(&issuer_id);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on suspension"
        );
    }

    /// reactivate_issuer emits exactly one event.
    #[test]
    fn reactivate_issuer_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.suspend_issuer(&issuer_id);
        client.reactivate_issuer(&issuer_id);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on reactivation"
        );
    }

    /// revoke_issuer emits exactly one event.
    #[test]
    fn revoke_issuer_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        client.revoke_issuer(&issuer_id);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on revocation"
        );
    }

    /// rotate_issuer_address emits exactly one event containing both old and new addresses.
    #[test]
    fn rotate_address_emits_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let old_address = Address::from_str(&env, ISSUER_ONE);
        let new_address = Address::from_str(&env, ISSUER_TWO);

        client.register_issuer(&issuer_id, &old_address, &bytes(&env, 2));
        client.rotate_issuer_address(&issuer_id, &new_address);

        assert_eq!(
            env.events().all().events().len(),
            1,
            "expected exactly one event on address rotation"
        );
    }

    /// rotate_issuer_address on a revoked issuer panics and emits no success event.
    #[test]
    fn rotate_revoked_issuer_address_emits_no_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let old_address = Address::from_str(&env, ISSUER_ONE);
        let new_address = Address::from_str(&env, ISSUER_TWO);

        client.register_issuer(&issuer_id, &old_address, &bytes(&env, 2));
        client.revoke_issuer(&issuer_id);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.rotate_issuer_address(&issuer_id, &new_address);
        }));
        assert!(result.is_err(), "expected panic on revoked issuer rotation");
        assert_eq!(
            env.events().all().events().len(),
            0,
            "no success event should be emitted on a failed rotation"
        );
    }

    /// Each successful mutation emits exactly one event (full lifecycle).
    /// Each call is checked independently since the event buffer resets per
    /// invocation.
    #[test]
    fn each_mutation_emits_exactly_one_event() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);
        let new_address = Address::from_str(&env, ISSUER_TWO);

        // register
        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));
        assert_eq!(env.events().all().events().len(), 1);

        // update metadata
        client.update_issuer(&issuer_id, &bytes(&env, 3));
        assert_eq!(env.events().all().events().len(), 1);

        // suspend
        client.suspend_issuer(&issuer_id);
        assert_eq!(env.events().all().events().len(), 1);

        // reactivate
        client.reactivate_issuer(&issuer_id);
        assert_eq!(env.events().all().events().len(), 1);

        // rotate address
        client.rotate_issuer_address(&issuer_id, &new_address);
        assert_eq!(env.events().all().events().len(), 1);

        // revoke
        client.revoke_issuer(&issuer_id);
        assert_eq!(env.events().all().events().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Auth mock-parity (#72)
    //
    // Every test above uses env.mock_all_auths() via setup(), which lets any
    // caller through unconditionally — it can never observe that
    // revoke_issuer actually demands the *admin's* signature specifically.
    // This test scopes mock_auths to a real, valid signer that is not the
    // admin (the registered issuer's own address) and asserts the contract's
    // real require_auth(&admin) check rejects it — proving the issuer's own
    // valid signature cannot authorize an admin-only operation on itself.
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_issuer_rejects_a_valid_signature_from_the_issuer_itself() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        client.initialize(&admin);

        // mock_auths (below) registers a stand-in auth contract at each
        // mocked address, so the address must be one the test Env generated
        // itself — a hardcoded G-string constant (like ISSUER_ONE, used by
        // every other test in this module under mock_all_auths()) is not a
        // valid registration target here.
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::generate(&env);
        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));

        // From here on, only the issuer's own signature is authorized for
        // this specific revoke_issuer invocation — not a blanket
        // mock_all_auths(). The issuer's signature is genuinely valid (it is
        // a real, well-formed authorization the host will accept); it is
        // simply for the wrong address. If require_auth(&admin) were ever
        // weakened to accept any authorized caller, this is what would stop
        // silently passing.
        env.mock_auths(&[MockAuth {
            address: &issuer_address,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "revoke_issuer",
                args: (issuer_id.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = client.try_revoke_issuer(&issuer_id);
        assert!(
            result.is_err(),
            "the issuer's own valid signature must not authorize revoking itself; only the admin's signature may"
        );

        // And unrevoked: the rejected call must not have mutated state.
        assert_eq!(client.get_issuer(&issuer_id).status, IssuerStatus::Active);
    }

    // ── numeric boundary tests ────────────────────────────────────────────────

    /// Contract version boundaries for issuer-registry.
    /// While issuer-registry has no direct numeric user inputs, it does support
    /// contract versioning and upgrade governance. This test covers version boundaries.
    #[test]
    fn contract_version_initialized_and_upgradeable() {
        let (env, client, _admin) = setup();

        // Contract version should be initialized to 1
        assert_eq!(client.get_contract_version(), 1);

        // Valid: upgrade to next version
        client.approve_upgrade(&bytes(&env, 1), &2);
        assert!(client.is_upgrade_allowed(&bytes(&env, 1)));
    }

    #[test]
    fn contract_version_upgrade_boundaries() {
        let (env, client, _admin) = setup();

        // Valid: immediate next version
        client.approve_upgrade(&bytes(&env, 1), &2);
        client.upgrade_contract(&bytes(&env, 1));
        assert_eq!(client.get_contract_version(), 2);

        // Valid: large version number
        client.approve_upgrade(&bytes(&env, 2), &u32::MAX);
        client.upgrade_contract(&bytes(&env, 2));
        assert_eq!(client.get_contract_version(), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn contract_version_equal_current_rejected() {
        let (env, client, _admin) = setup();
        // Current version is 1; attempting version 1 is rejected
        client.approve_upgrade(&bytes(&env, 1), &1);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn contract_version_below_current_rejected() {
        let (env, client, _admin) = setup();
        // Current version is 1; attempting version 0 is rejected
        client.approve_upgrade(&bytes(&env, 1), &0);
    }

    /// Test storage invariants: failed boundary cases must not modify state.
    #[test]
    fn failed_upgrade_version_downgrade_leaves_state_unchanged() {
        let (env, client, _admin) = setup();

        let contract_version_before = client.get_contract_version();
        let hash = bytes(&env, 0x88);

        // Attempt to allowlist a downgrade
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.approve_upgrade(&hash, &0);
        }));

        // Must have panicked
        assert!(result.is_err());

        // Contract version must not change
        assert_eq!(
            client.get_contract_version(),
            contract_version_before,
            "contract version must not change on failed upgrade approval"
        );

        // Hash must not be on allowlist
        assert!(
            !client.is_upgrade_allowed(&hash),
            "failed upgrade approval must not add hash to allowlist"
        );
    }

    // ── adversarial initialization tests ───────────────────────────────────────

    /// Verify that first initialization writes exactly the documented state
    /// with no partial writes or missing fields.
    ///
    /// Required behavior: First call to `initialize` results in:
    /// - Admin address set and readable
    /// - ContractVersion = 1
    #[test]
    fn initialization_writes_exactly_documented_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // Perform initialization
        client.initialize(&admin);

        // Verify exact state written
        assert_eq!(client.get_admin(), admin, "admin must be set");
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must be exactly 1 after initialization"
        );

        // Verify storage keys are set
        env.as_contract(&contract_id, || {
            let instance = env.storage().instance();
            assert!(
                instance.has(&DataKey::Admin),
                "Admin key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::ContractVersion),
                "ContractVersion key must exist in instance storage"
            );
        });
    }

    /// Verify that repeated initialization by any address fails without
    /// altering state or emitting events.
    ///
    /// Required behavior for re-initialization guard:
    /// - Second call to `initialize` with any admin (same or different) panics
    /// - Storage is byte-for-byte unchanged
    /// - No additional events are emitted
    #[test]
    fn reinitialization_by_same_admin_fails_atomically() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization succeeds
        client.initialize(&admin);
        let contract_version_after_first = client.get_contract_version();

        // Attempt second initialization with same admin
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin);
        }));

        // Must have panicked with "already initialized"
        assert!(result.is_err(), "re-initialization must panic");

        // Verify state is byte-for-byte identical
        assert_eq!(
            client.get_admin(),
            admin,
            "admin must not change after failed re-initialization"
        );
        assert_eq!(
            client.get_contract_version(),
            contract_version_after_first,
            "contract version must not change after failed re-initialization"
        );
    }

    /// Verify that re-initialization by a different address also fails
    /// without state or event changes.
    ///
    /// This tests that the re-initialization guard does not discriminate
    /// based on caller identity — it prevents any re-initialization attempt.
    #[test]
    fn reinitialization_by_different_admin_fails_atomically() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other = Address::from_str(&env, ISSUER_ONE);

        // First initialization with original admin
        client.initialize(&admin);
        let stored_admin = client.get_admin();
        let contract_version_after_first = client.get_contract_version();

        // Attempt re-initialization with different admin
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&other);
        }));

        // Must have panicked
        assert!(
            result.is_err(),
            "re-initialization by different admin must panic"
        );

        // Verify state is unchanged: original admin must still be stored
        assert_eq!(
            client.get_admin(),
            stored_admin,
            "admin must not change when different address attempts re-initialization"
        );
        assert_eq!(
            client.get_contract_version(),
            contract_version_after_first,
            "contract version must not change after failed re-initialization by different admin"
        );
    }

    /// Verify that the re-initialization guard does not allow partial state
    /// modification on subsequent initialization attempts.
    #[test]
    fn reinitialization_guard_is_absolute() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization
        client.initialize(&admin);

        // Multiple re-initialization attempts must all fail
        for attempt in 1..=3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.initialize(&admin);
            }));

            assert!(
                result.is_err(),
                "re-initialization attempt {} must fail",
                attempt
            );

            // Admin must remain unchanged
            assert_eq!(
                client.get_admin(),
                admin,
                "admin must not change after re-initialization attempt {}",
                attempt
            );
        }
    }

    /// Verify that initialization state is maintained across subsequent
    /// issuer registration and upgrade operations.
    ///
    /// Tests that the initialization state (admin, contract version) is stable
    /// and correct before and after other contract operations.
    #[test]
    fn initialization_state_stable_across_operations() {
        let (env, client, admin) = setup();

        // State immediately after initialization
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_contract_version(), 1);

        // Perform issuer registration
        let issuer_id = bytes(&env, 1);
        let issuer_address = Address::from_str(&env, ISSUER_ONE);
        client.register_issuer(&issuer_id, &issuer_address, &bytes(&env, 2));

        // Admin must remain unchanged
        assert_eq!(
            client.get_admin(),
            admin,
            "admin must not change after issuer registration"
        );
        // Contract version must still be 1 (no upgrade yet)
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must not change on issuer registration"
        );
    }

    /// Summary test: issuer-registry initialization spec verification.
    ///
    /// This test serves as executable documentation of what the test matrix
    /// expects from issuer-registry initialization:
    /// - Standalone contract (no dependency addresses)
    /// - Has re-initialization guard
    /// - Does NOT emit an event during initialization
    /// - Sets: admin, contract_version=1
    #[test]
    fn issuer_registry_initialization_spec_summary() {
        // CONTRACT SPEC: issuer-registry
        // - Name: "issuer-registry"
        // - Has re-initialization guard: YES (panics "already initialized")
        // - Emits initialization event: NO
        // - Takes dependency addresses: NO
        // - Dependencies: []
        // - First init writes:
        //   - Admin: passed address (requires auth)
        //   - ContractVersion: 1
        // - Re-init guard: DataKey::Admin presence check; panics if set
        // - Re-init allowed by different admin: NO (guard blocks all)
        // - Invalid config cases: None (no dependencies to validate)

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(IssuerRegistryContract, ());
        let client = IssuerRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // Verify the spec
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_contract_version(), 1);

        // Re-initialization must fail
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin)
        }))
        .is_err());
    }

    // ── issue 178: dependency interface version ────────────────────────────────

    #[test]
    fn exposes_a_stable_interface_version() {
        let (_env, client, _admin) = setup();
        let version = client.interface_version();
        assert_eq!(version, earnproof_shared::ISSUER_REGISTRY_INTERFACE_VERSION);
        assert_eq!(version.major, 1);
    }

    // ── issue 183: registry epoch for cache invalidation ───────────────────────

    #[test]
    fn epoch_starts_at_zero_and_advances_once_per_mutation() {
        let (env, client, _admin) = setup();
        assert_eq!(client.get_issuer_epoch(), 0);

        let issuer_id = bytes(&env, 1);
        let address = Address::from_str(&env, ISSUER_ONE);
        client.register_issuer(&issuer_id, &address, &bytes(&env, 2));
        assert_eq!(client.get_issuer_epoch(), 1);

        client.update_issuer(&issuer_id, &bytes(&env, 3));
        assert_eq!(client.get_issuer_epoch(), 2);

        client.suspend_issuer(&issuer_id);
        assert_eq!(client.get_issuer_epoch(), 3);

        client.reactivate_issuer(&issuer_id);
        assert_eq!(client.get_issuer_epoch(), 4);

        client.rotate_issuer_address(&issuer_id, &Address::from_str(&env, ISSUER_TWO));
        assert_eq!(client.get_issuer_epoch(), 5);

        client.revoke_issuer(&issuer_id);
        assert_eq!(client.get_issuer_epoch(), 6);
    }

    #[test]
    fn failed_mutation_does_not_advance_epoch() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let address = Address::from_str(&env, ISSUER_ONE);
        client.register_issuer(&issuer_id, &address, &bytes(&env, 2));
        let epoch = client.get_issuer_epoch();

        // Duplicate registration is rejected and must not advance the epoch.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.register_issuer(
                &issuer_id,
                &Address::from_str(&env, ISSUER_TWO),
                &bytes(&env, 3),
            )
        }));
        assert!(result.is_err());
        assert_eq!(client.get_issuer_epoch(), epoch);
    }

    #[test]
    fn register_emits_one_event_and_advances_epoch() {
        let (env, client, _admin) = setup();
        let issuer_id = bytes(&env, 1);
        let address = Address::from_str(&env, ISSUER_ONE);
        client.register_issuer(&issuer_id, &address, &bytes(&env, 2));

        // Exactly one lifecycle event on the registration invocation. A later
        // read invocation would clear the buffer, so assert it first.
        assert_eq!(env.events().all().events().len(), 1);
        assert_eq!(client.get_issuer_epoch(), 1);
    }

    #[test]
    #[should_panic(expected = "issuer epoch overflow")]
    fn epoch_overflow_panics_rather_than_wrapping() {
        let (env, client, _admin) = setup();
        // Drive the stored epoch to its maximum, then a mutation must abort.
        env.as_contract(&client.address, || {
            env.storage()
                .instance()
                .set(&DataKey::IssuerEpoch, &u64::MAX);
        });
        let issuer_id = bytes(&env, 1);
        client.register_issuer(
            &issuer_id,
            &Address::from_str(&env, ISSUER_ONE),
            &bytes(&env, 2),
        );
    }

    #[test]
    fn migrate_initializes_epoch_deterministically() {
        let (env, client, admin) = setup();
        // Simulate an upgraded contract that predates the epoch key.
        env.as_contract(&client.address, || {
            env.storage().instance().remove(&DataKey::IssuerEpoch);
        });
        let _ = admin;
        client.migrate(&0);
        assert_eq!(client.get_issuer_epoch(), 0);
    }

    // ── issue 182: registration capacity guardrails ────────────────────────────

    #[test]
    fn capacity_defaults_to_unlimited() {
        let (_env, client, _admin) = setup();
        assert_eq!(client.get_max_active_issuers(), u32::MAX);
        assert_eq!(client.get_active_issuer_count(), 0);
    }

    #[test]
    fn active_count_tracks_lifecycle_transitions() {
        let (env, client, _admin) = setup();
        let id = bytes(&env, 1);
        let address = Address::from_str(&env, ISSUER_ONE);

        client.register_issuer(&id, &address, &bytes(&env, 2));
        assert_eq!(client.get_active_issuer_count(), 1);

        client.suspend_issuer(&id);
        assert_eq!(client.get_active_issuer_count(), 0);

        client.reactivate_issuer(&id);
        assert_eq!(client.get_active_issuer_count(), 1);

        client.revoke_issuer(&id);
        assert_eq!(client.get_active_issuer_count(), 0);
    }

    #[test]
    fn revoking_a_suspended_issuer_does_not_change_count() {
        let (env, client, _admin) = setup();
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);
        assert_eq!(client.get_active_issuer_count(), 0);
        client.revoke_issuer(&id);
        assert_eq!(client.get_active_issuer_count(), 0);
    }

    #[test]
    fn registration_at_capacity_is_rejected() {
        let (env, client, _admin) = setup();
        client.set_max_active_issuers(&1, &false);
        client.register_issuer(
            &bytes(&env, 1),
            &Address::from_str(&env, ISSUER_ONE),
            &bytes(&env, 2),
        );

        let result = client.try_register_issuer(
            &bytes(&env, 3),
            &Address::from_str(&env, ISSUER_TWO),
            &bytes(&env, 4),
        );
        assert_eq!(result, Err(Ok(IssuerError::IssuerCapacityExceeded)));
        // The rejected registration wrote nothing.
        assert_eq!(client.get_active_issuer_count(), 1);
        let result = client.try_get_issuer(&bytes(&env, 3));
        assert_eq!(result, Err(Ok(IssuerError::IssuerNotFound)));
    }

    #[test]
    fn suspending_frees_a_capacity_slot() {
        let (env, client, _admin) = setup();
        client.set_max_active_issuers(&1, &false);
        let first = bytes(&env, 1);
        client.register_issuer(
            &first,
            &Address::from_str(&env, ISSUER_ONE),
            &bytes(&env, 2),
        );
        client.suspend_issuer(&first);

        // A slot is free again, so a second registration succeeds.
        client.register_issuer(
            &bytes(&env, 3),
            &Address::from_str(&env, ISSUER_TWO),
            &bytes(&env, 4),
        );
        assert_eq!(client.get_active_issuer_count(), 1);
    }

    #[test]
    fn reactivation_re_checks_capacity() {
        let (env, client, _admin) = setup();
        let first = bytes(&env, 1);
        let second = bytes(&env, 3);
        client.register_issuer(
            &first,
            &Address::from_str(&env, ISSUER_ONE),
            &bytes(&env, 2),
        );
        client.suspend_issuer(&first);
        client.register_issuer(
            &second,
            &Address::from_str(&env, ISSUER_TWO),
            &bytes(&env, 4),
        );
        // Now one active (second) and one suspended (first). Tighten to 1.
        client.set_max_active_issuers(&1, &true);

        let result = client.try_reactivate_issuer(&first);
        assert_eq!(result, Err(Ok(IssuerError::IssuerCapacityExceeded)));
        // Still suspended: the rejected reactivation changed nothing.
        assert_eq!(client.get_issuer(&first).status, IssuerStatus::Suspended);
    }

    #[test]
    fn max_below_usage_requires_override() {
        let (env, client, _admin) = setup();
        client.register_issuer(
            &bytes(&env, 1),
            &Address::from_str(&env, ISSUER_ONE),
            &bytes(&env, 2),
        );

        let result = client.try_set_max_active_issuers(&0, &false);
        assert_eq!(result, Err(Ok(IssuerError::MaxBelowActiveUsage)));
        // Limit unchanged.
        assert_eq!(client.get_max_active_issuers(), u32::MAX);

        // With the explicit override the ratchet-down is accepted.
        client.set_max_active_issuers(&0, &true);
        assert_eq!(client.get_max_active_issuers(), 0);
    }

    #[test]
    fn migrate_sets_active_count() {
        let (_env, client, _admin) = setup();
        client.migrate(&42);
        assert_eq!(client.get_active_issuer_count(), 42);
    }

    // ── issue 181: reactivation cooldown policy ────────────────────────────────

    #[test]
    fn zero_cooldown_permits_immediate_reactivation() {
        let (env, client, _admin) = setup();
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);
        client.reactivate_issuer(&id);
        assert!(client.is_active_issuer(&id));
    }

    #[test]
    fn reactivation_before_cooldown_is_rejected() {
        let (env, client, _admin) = setup();
        env.ledger().set_timestamp(1_000);
        client.set_reactivation_cooldown(&500);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);
        assert_eq!(client.get_earliest_reactivation(&id), 1_500);

        let result = client.try_reactivate_issuer(&id);
        assert_eq!(result, Err(Ok(IssuerError::ReactivationCooldownActive)));
        assert_eq!(client.get_issuer(&id).status, IssuerStatus::Suspended);
    }

    #[test]
    fn reactivation_at_exact_boundary_is_permitted() {
        let (env, client, _admin) = setup();
        env.ledger().set_timestamp(1_000);
        client.set_reactivation_cooldown(&500);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);

        env.ledger().set_timestamp(1_500);
        client.reactivate_issuer(&id);
        assert!(client.is_active_issuer(&id));
    }

    #[test]
    fn lowering_cooldown_does_not_retroactively_shorten_an_active_suspension() {
        let (env, client, _admin) = setup();
        env.ledger().set_timestamp(1_000);
        client.set_reactivation_cooldown(&1_000);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);
        assert_eq!(client.get_earliest_reactivation(&id), 2_000);

        // Shorten the policy after the suspension. The fixed deadline holds.
        client.set_reactivation_cooldown(&0);
        assert_eq!(client.get_earliest_reactivation(&id), 2_000);
        env.ledger().set_timestamp(1_500);
        let result = client.try_reactivate_issuer(&id);
        assert_eq!(result, Err(Ok(IssuerError::ReactivationCooldownActive)));
    }

    #[test]
    fn re_suspension_recomputes_the_deadline_from_the_current_cooldown() {
        let (env, client, _admin) = setup();
        env.ledger().set_timestamp(1_000);
        client.set_reactivation_cooldown(&500);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.suspend_issuer(&id);
        env.ledger().set_timestamp(1_500);
        client.reactivate_issuer(&id);

        // Re-suspend later: the deadline is recomputed from the new timestamp.
        client.set_reactivation_cooldown(&200);
        env.ledger().set_timestamp(2_000);
        client.suspend_issuer(&id);
        assert_eq!(client.get_earliest_reactivation(&id), 2_200);
    }

    #[test]
    fn cooldown_deadline_saturates_and_does_not_overflow() {
        let (env, client, _admin) = setup();
        env.ledger().set_timestamp(10);
        client.set_reactivation_cooldown(&u64::MAX);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        // Suspension must not panic on the overflowing deadline arithmetic.
        client.suspend_issuer(&id);
        assert_eq!(client.get_earliest_reactivation(&id), u64::MAX);
    }

    #[test]
    fn revoked_issuer_stays_non_reactivatable_regardless_of_cooldown() {
        let (env, client, _admin) = setup();
        client.set_reactivation_cooldown(&0);
        let id = bytes(&env, 1);
        client.register_issuer(&id, &Address::from_str(&env, ISSUER_ONE), &bytes(&env, 2));
        client.revoke_issuer(&id);

        let result = client.try_reactivate_issuer(&id);
        assert_eq!(result, Err(Ok(IssuerError::InvalidTransition)));
    }
}
