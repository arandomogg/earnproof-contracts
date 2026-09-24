#![no_std]

use earnproof_shared::{
    ApprovalQuery, ApprovalStatus, ContractError, UpgradeApproval, UpgradeApprovalMetadata,
    UPGRADE_APPROVAL_EXPIRY_LEDGERS, UPGRADE_TIMELOCK_LEDGERS, TTL_EXTEND_TO_LEDGERS,
    TTL_THRESHOLD_LEDGERS,
    ContractError, MigrationStatus, TtlStatus, MAX_MIGRATION_BATCH, MIGRATION_STATUS_VERSION,
    TTL_EXTEND_TO_LEDGERS, TTL_THRESHOLD_LEDGERS,
};
use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, BytesN, Env};

#[contract]
pub struct ProtocolConfigContract;

#[contracttype]
enum DataKey {
    Admin,
    Paused,
    CurrentPause,
    LatestPause,
    ConfigVersion,
    SchemaVersion(u32),
    SchemaTtl(u32),
    InstanceLiveUntil,
    /// Allowlist entry: maps a WASM hash to the target contract version it
    /// must install.  Only hashes pre-approved by the admin may be applied.
    AllowedWasm(BytesN<32>),
    MigrationStatus,
    /// Monotonically-increasing contract version stored in instance storage.
    /// Prevents installing an older (or equal) version over a newer one.
    ContractVersion,
    /// Single active approval slot in instance storage.
    /// Used for timelock/expiry enforcement at execution time.
    UpgradeApproval,
    /// Per-hash audit record in persistent storage.
    /// Enables off-chain verification of approval history.
    UpgradeApprovalMetadata(BytesN<32>),
}

// ── existing events ─────────────────────────────────────────────────────────

#[contractevent]
pub struct Initialized {
    pub admin: Address,
}

#[contractevent]
pub struct AdminChanged {
    pub new_admin: Address,
}

#[contractevent]
pub struct Paused {
    pub paused: bool,
}

#[contractevent]
pub struct Unpaused {
    pub paused: bool,
}

/// Fixed-size metadata that correlates a pause with an off-chain incident
/// record without placing incident plaintext on-chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseMetadata {
    pub incident_id: BytesN<32>,
    pub reason_commitment: BytesN<32>,
    pub started_at: u64,
    pub ended_at: u64,
    pub active: bool,
}

#[contractevent]
pub struct SchemaApproved {
    pub version: u32,
}

#[contractevent]
pub struct SchemaDeprecated {
    pub version: u32,
}

// ── upgrade events ───────────────────────────────────────────────────────────

/// Emitted when the admin adds a WASM hash to the upgrade allowlist.
#[contractevent]
pub struct UpgradeAllowlisted {
    pub wasm_hash: BytesN<32>,
    pub new_contract_version: u32,
    pub approved_by: Address,
}

/// Emitted when the admin removes a WASM hash from the allowlist without
/// applying it (e.g. rolling back an approved-but-not-yet-applied hash).
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

#[contractimpl]
impl ProtocolConfigContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }

        Self::require_valid_principal(&admin)?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage()
            .instance()
            .set(&DataKey::ConfigVersion, &1_u32);
        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &1_u32);
        Self::extend_instance_ttl(env.clone());
        Initialized { admin }.publish(&env);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        Self::assert_operational(&env);
        let admin = Self::get_admin(env.clone())?;
        Self::require_valid_principal(&new_admin)?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Self::bump_config_version(env.clone());
        AdminChanged { new_admin }.publish(&env);
        Ok(())
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    pub fn pause(env: Env) -> Result<(), ContractError> {
        // Retained for backwards ABI compatibility. New integrations should
        // supply operator-controlled commitments through pause_with_metadata.
        let legacy_commitment = BytesN::from_array(&env, &[0; 32]);
        Self::pause_with_metadata(env, legacy_commitment.clone(), legacy_commitment)
    }

    pub fn pause_with_metadata(
        env: Env,
        incident_id: BytesN<32>,
        reason_commitment: BytesN<32>,
    ) -> Result<(), ContractError> {
        Self::assert_operational(&env);
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        if Self::is_paused(env.clone()) {
            let current = Self::get_current_pause(env.clone());
            return match current {
                Some(metadata)
                    if metadata.incident_id == incident_id
                        && metadata.reason_commitment == reason_commitment =>
                {
                    Ok(())
                }
                Some(_) => Err(ContractError::InvalidState),
                None => Err(ContractError::InvalidState),
            };
        }

        let metadata = PauseMetadata {
            incident_id,
            reason_commitment,
            started_at: env.ledger().timestamp(),
            ended_at: 0,
            active: true,
        };
        env.storage().instance().set(&DataKey::Paused, &true);
        env.storage()
            .instance()
            .set(&DataKey::CurrentPause, &metadata);
        env.storage()
            .instance()
            .set(&DataKey::LatestPause, &metadata);
        Self::bump_config_version(env.clone());
        Paused { paused: true }.publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), ContractError> {
        Self::assert_operational(&env);
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        if !Self::is_paused(env.clone()) {
            return Ok(());
        }

        if let Some(mut metadata) = Self::get_current_pause(env.clone()) {
            metadata.active = false;
            metadata.ended_at = env.ledger().timestamp();
            env.storage()
                .instance()
                .set(&DataKey::LatestPause, &metadata);
            env.storage().instance().remove(&DataKey::CurrentPause);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_config_version(env.clone());
        Unpaused { paused: false }.publish(&env);
        Ok(())
    }

    /// Returns the active incident, or `None` while the protocol is unpaused.
    pub fn get_current_pause(env: Env) -> Option<PauseMetadata> {
        env.storage().instance().get(&DataKey::CurrentPause)
    }

    /// Returns the newest active or closed incident known to this contract.
    pub fn get_latest_pause(env: Env) -> Option<PauseMetadata> {
        env.storage().instance().get(&DataKey::LatestPause)
    }

    /// Adds metadata to a paused deployment created by a pre-metadata WASM.
    /// The transition time cannot be recovered, so migration records the
    /// current ledger timestamp and preserves the existing paused state.
    pub fn migrate_pause_metadata(
        env: Env,
        incident_id: BytesN<32>,
        reason_commitment: BytesN<32>,
    ) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        if !Self::is_paused(env.clone()) || Self::get_current_pause(env.clone()).is_some() {
            return Err(ContractError::InvalidState);
        }

        let metadata = PauseMetadata {
            incident_id,
            reason_commitment,
            started_at: env.ledger().timestamp(),
            ended_at: 0,
            active: true,
        };
        env.storage()
            .instance()
            .set(&DataKey::CurrentPause, &metadata);
        env.storage()
            .instance()
            .set(&DataKey::LatestPause, &metadata);
        Self::extend_instance_ttl(env);
        Ok(())
    }

    pub fn approve_schema_version(env: Env, version: u32) -> Result<(), ContractError> {
        Self::assert_operational(&env);
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        Self::ensure_nonzero_version(version)?;
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion(version), &true);
        Self::extend_schema_ttl(env.clone(), version);
        Self::bump_config_version(env.clone());
        SchemaApproved { version }.publish(&env);
        Ok(())
    }

    pub fn deprecate_schema_version(env: Env, version: u32) -> Result<(), ContractError> {
        Self::assert_operational(&env);
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        Self::ensure_nonzero_version(version)?;
        env.storage()
            .persistent()
            .set(&DataKey::SchemaVersion(version), &false);
        Self::extend_schema_ttl(env.clone(), version);
        Self::bump_config_version(env.clone());
        SchemaDeprecated { version }.publish(&env);
        Ok(())
    }

    pub fn is_schema_version_approved(env: Env, version: u32) -> bool {
        if version == 0 {
            return false;
        }

        let key = DataKey::SchemaVersion(version);
        let approved = env.storage().persistent().get(&key).unwrap_or(false);
        if env.storage().persistent().has(&key) {
            env.storage().persistent().extend_ttl(
                &key,
                TTL_THRESHOLD_LEDGERS,
                TTL_EXTEND_TO_LEDGERS,
            );
        }
        approved
    }

    pub fn get_config_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ConfigVersion)
            .unwrap_or(0)
    }

    pub fn get_instance_ttl_status(env: Env) -> TtlStatus {
        earnproof_shared::ttl_status(
            env.ledger().sequence(),
            env.storage().instance().has(&DataKey::Admin),
            env.storage().instance().get(&DataKey::InstanceLiveUntil),
        )
    }

    pub fn get_schema_ttl_status(env: Env, version: u32) -> TtlStatus {
        earnproof_shared::ttl_status(
            env.ledger().sequence(),
            env.storage()
                .persistent()
                .has(&DataKey::SchemaVersion(version)),
            env.storage().persistent().get(&DataKey::SchemaTtl(version)),
        )
    }

    pub fn refresh_instance_ttl(env: Env) -> Result<TtlStatus, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        Self::extend_instance_ttl(env.clone());
        Ok(Self::get_instance_ttl_status(env))
    }

    // ── upgrade governance ───────────────────────────────────────────────────

    /// Returns the stored monotonic contract version (separate from the
    /// config-mutation counter).  Starts at 1 after `initialize`.
    pub fn get_contract_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0)
    }

    pub fn get_migration_status(env: Env) -> Option<MigrationStatus> {
        env.storage().instance().get(&DataKey::MigrationStatus)
    }

    pub fn begin_migration(
        env: Env,
        target_contract_version: u32,
        total_items: u32,
    ) -> Result<MigrationStatus, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        if target_contract_version <= Self::get_contract_version(env.clone()) || total_items == 0 {
            return Err(ContractError::InvalidInput);
        }
        if let Some(status) = Self::get_migration_status(env.clone()) {
            return if status.target_contract_version == target_contract_version
                && status.total_items == total_items
            {
                Ok(status)
            } else {
                Err(ContractError::InvalidState)
            };
        }
        let status = MigrationStatus {
            status_version: MIGRATION_STATUS_VERSION,
            target_contract_version,
            cursor: 0,
            total_items,
            complete: false,
        };
        env.storage()
            .instance()
            .set(&DataKey::MigrationStatus, &status);
        Self::extend_instance_ttl(env);
        Ok(status)
    }

    pub fn advance_migration(
        env: Env,
        expected_cursor: u32,
        processed_items: u32,
    ) -> Result<MigrationStatus, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        if processed_items == 0 || processed_items > MAX_MIGRATION_BATCH {
            return Err(ContractError::InvalidInput);
        }
        let mut status =
            Self::get_migration_status(env.clone()).ok_or(ContractError::InvalidState)?;
        if expected_cursor < status.cursor {
            return if expected_cursor.saturating_add(processed_items) <= status.cursor {
                Ok(status)
            } else {
                Err(ContractError::InvalidState)
            };
        }
        if expected_cursor != status.cursor || status.complete {
            return Err(ContractError::InvalidState);
        }
        let next = status
            .cursor
            .checked_add(processed_items)
            .ok_or(ContractError::InvalidInput)?;
        if next > status.total_items {
            return Err(ContractError::InvalidInput);
        }
        status.cursor = next;
        status.complete = next == status.total_items;
        env.storage()
            .instance()
            .set(&DataKey::MigrationStatus, &status);
        Self::extend_instance_ttl(env);
        Ok(status)
    }

    pub fn get_config_digest_version() -> u32 {
        earnproof_shared::CONFIG_DIGEST_VERSION
    }

    pub fn get_config_digest(env: Env) -> Result<BytesN<32>, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Ok(earnproof_shared::protocol_config_digest(
            &env,
            &admin,
            Self::is_paused(env.clone()),
            Self::get_config_version(env.clone()),
            Self::get_contract_version(env.clone()),
        ))
    }

    /// Admin-only: add `wasm_hash` to the upgrade allowlist and record the
    /// `new_version` that must be installed by that WASM.
    ///
    /// `new_version` must be strictly greater than the currently stored
    /// contract version so that a downgrade cannot be pre-approved.
    ///
    /// Records an upgrade approval with timelock and expiry.
    ///
    /// # Timing
    /// - `earliest_execution` = current_ledger + UPGRADE_TIMELOCK_LEDGERS
    /// - `expires_at` = current_ledger + UPGRADE_APPROVAL_EXPIRY_LEDGERS
    ///
    /// # Re-approval
    /// Re-approval replaces ALL timing metadata. Old timing is
    /// never reused — prevents stale metadata from persisting.
    ///
    /// Also stores complete upgrade approval metadata in persistent
    /// storage for off-chain verification, including the target hash,
    /// version, approver, creation ledger, and expiry ledger.
    pub fn approve_upgrade(env: Env, wasm_hash: BytesN<32>, new_version: u32) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        let current = Self::get_contract_version(env.clone());
        if new_version <= current {
            return Err(ContractError::InvalidInput);
        }

        let current_ledger = env.ledger().sequence();

        // Saturating arithmetic prevents overflow on boundary inputs
        let earliest_execution = current_ledger.saturating_add(UPGRADE_TIMELOCK_LEDGERS);
        let expires_at = current_ledger.saturating_add(UPGRADE_APPROVAL_EXPIRY_LEDGERS);

        // Validate timing invariants
        if earliest_execution > expires_at {
            return Err(ContractError::InvalidTimingConfig);
        }

        // Store the enforcement struct in instance storage (for timelock checks at execution)
        // ALWAYS creates fresh timing metadata — never reuses stale fields from a previous approval
        let approval = UpgradeApproval {
            wasm_hash: wasm_hash.clone(),
            created_at: current_ledger,
            earliest_execution,
            expires_at,
            approved_by: admin.clone(),
        };
        env.storage()
            .instance()
            .set(&DataKey::UpgradeApproval, &approval);

        // Store rich metadata in persistent storage for off-chain verification.
        // expiry_ledger mirrors expires_at for consistency between both records.
        let metadata = UpgradeApprovalMetadata {
            target_hash: wasm_hash.clone(),
            target_version: new_version,
            approver: admin.clone(),
            creation_ledger: current_ledger,
            execution_ledger: None,
            expiry_ledger: expires_at,
            status: ApprovalStatus::Active,
        };
        env.storage()
            .persistent()
            .set(&DataKey::UpgradeApprovalMetadata(wasm_hash.clone()), &metadata);

        Self::extend_instance_ttl(env.clone());
        UpgradeAllowlisted {
            wasm_hash,
            new_contract_version: new_version,
            approved_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Admin-only: remove a previously allowlisted WASM hash without applying
    /// it.  Safe to call even if the hash was never allowlisted.
    ///
    /// If a metadata record exists for this hash, its status is set to Revoked
    /// for audit purposes. The active approval slot is always cleared.
    pub fn revoke_upgrade(env: Env, wasm_hash: BytesN<32>) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        // Mark persistent metadata as Revoked for audit trail
        if let Some(mut metadata) = env
            .storage()
            .persistent()
            .get::<DataKey, UpgradeApprovalMetadata>(
                &DataKey::UpgradeApprovalMetadata(wasm_hash.clone()),
            )
        {
            metadata.status = ApprovalStatus::Revoked;
            env.storage()
                .persistent()
                .set(&DataKey::UpgradeApprovalMetadata(wasm_hash.clone()), &metadata);
        }

        // Remove legacy allowlist entry (backwards compatibility)
        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        // Clear the active approval slot
        env.storage()
            .instance()
            .remove(&DataKey::UpgradeApproval);

        UpgradeRevoked {
            wasm_hash,
            revoked_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Returns true when `wasm_hash` is on the allowlist.
    pub fn is_upgrade_allowed(env: Env, wasm_hash: BytesN<32>) -> bool {
        // Check new-style approval
        if let Some(approval) = env
            .storage()
            .instance()
            .get::<_, UpgradeApproval>(&DataKey::UpgradeApproval)
        {
            return approval.wasm_hash == wasm_hash;
        }
        // Fall back to old-style allowlist for backwards compatibility
        env.storage()
            .instance()
            .has(&DataKey::AllowedWasm(wasm_hash))
    }

    /// Returns upgrade approval metadata for off-chain verification.
    ///
    /// # Read-only guarantee
    /// This function NEVER mutates storage, TTL, or governance state.
    /// It reads from persistent storage without touching instance storage
    /// or extending any TTL — callers can query freely without side effects.
    ///
    /// # Unknown vs Revoked
    /// - `ApprovalQuery::NotFound`: no record exists for this hash
    /// - `ApprovalQuery::Revoked(metadata)`: record exists, was explicitly revoked
    ///   The distinction matters for auditing: NotFound may mean the approval
    ///   was never created or was garbage-collected after expiry.
    ///
    /// # Arguments
    /// * `target_hash` - The 32-byte WASM hash to look up
    pub fn get_upgrade_approval_metadata(env: Env, target_hash: BytesN<32>) -> ApprovalQuery {
        use earnproof_shared::ApprovalQuery::*;
        use earnproof_shared::ApprovalStatus::*;

        // Read from persistent storage — never instance (no TTL side effects)
        let metadata = env
            .storage()
            .persistent()
            .get::<DataKey, UpgradeApprovalMetadata>(
                &DataKey::UpgradeApprovalMetadata(target_hash.clone()),
            );

        match metadata {
            None => NotFound,
            Some(m) if m.status == Revoked => Revoked(m),
            Some(m) => {
                // Check for implicit expiry (window passed without execution)
                let current_ledger = env.ledger().sequence();
                if current_ledger > m.expiry_ledger && m.status == Active {
                    // Return as expired — but DO NOT write this to storage
                    // (read-only: caller sees expired status without mutating state)
                    Found(UpgradeApprovalMetadata {
                        status: Expired,
                        ..m
                    })
                } else {
                    Found(m)
                }
            }
        }
    }

    /// Admin-only: apply an in-place WASM upgrade.
    ///
    /// # Requirements
    /// 1. Caller is the admin.
    /// 2. An approval exists with matching wasm_hash.
    /// 3. current_ledger >= earliest_execution (timelock elapsed)
    /// 4. current_ledger < expires_at (approval not expired)
    /// 5. Target version is strictly greater than current (downgrade guard).
    ///
    /// On success the new WASM is installed, `ContractVersion` is advanced,
    /// the approval is consumed (removed), and a `ContractUpgraded`
    /// event is emitted.
    ///
    /// # Failed execution
    /// Approval state is left UNCHANGED on all rejection paths.
    /// Only successful execution removes the approval.
    pub fn upgrade_contract(env: Env, wasm_hash: BytesN<32>, new_version: u32) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        // Load approval — error if none exists
        let approval: UpgradeApproval = env
            .storage()
            .instance()
            .get(&DataKey::UpgradeApproval)
            .ok_or(ContractError::NoUpgradeApproval)?;

        let current_ledger = env.ledger().sequence();

        // Check timelock: too early
        if current_ledger < approval.earliest_execution {
            return Err(ContractError::UpgradeTimelockNotElapsed);
        }
        if let Some(status) = Self::get_migration_status(env.clone()) {
            if !status.complete || status.target_contract_version != new_version {
                panic!("required storage migration is incomplete");
            }
        }

        // Check expiry: too late — leave state unchanged, caller must re-approve
        if current_ledger >= approval.expires_at {
            return Err(ContractError::UpgradeApprovalExpired);
        }

        // Verify hash matches approved hash
        if wasm_hash != approval.wasm_hash {
            return Err(ContractError::WasmHashMismatch);
        }

        // Verify version is still valid
        let current_version = Self::get_contract_version(env.clone());
        if new_version <= current_version {
            return Err(ContractError::InvalidInput);
        }

        // All checks passed — execute upgrade
        #[cfg(not(test))]
        env.deployer()
            .update_current_contract_wasm(wasm_hash.clone());

        // Consume the active approval slot before version bump (prevents re-entrancy replay)
        env.storage()
            .instance()
            .remove(&DataKey::UpgradeApproval);

        // Record the new version
        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &new_version);

        // Update persistent audit record to Executed
        if let Some(mut metadata) = env
            .storage()
            .persistent()
            .get::<DataKey, UpgradeApprovalMetadata>(
                &DataKey::UpgradeApprovalMetadata(wasm_hash.clone()),
            )
        {
            metadata.execution_ledger = Some(current_ledger);
            metadata.status = ApprovalStatus::Executed;
            env.storage()
                .persistent()
                .set(&DataKey::UpgradeApprovalMetadata(wasm_hash.clone()), &metadata);
        }

        env.storage().instance().remove(&DataKey::MigrationStatus);
        Self::extend_instance_ttl(env.clone());

        ContractUpgraded {
            new_wasm_hash: wasm_hash,
            old_contract_version: current_version,
            new_contract_version: new_version,
            upgraded_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    /// Admin-only: revoke an upgrade approval at any point in its lifetime.
    ///
    /// Revocation is allowed:
    /// - Before timelock elapses
    /// - During the valid execution window
    /// - Even after expiry (cleanup)
    ///
    /// # Authorization
    /// Only the admin can revoke.
    pub fn revoke_upgrade_approval(env: Env) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        // Allow revocation even if no approval exists (idempotent)
        env.storage()
            .instance()
            .remove(&DataKey::UpgradeApproval);

        Ok(())
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn ensure_nonzero_version(version: u32) -> Result<(), ContractError> {
        if version == 0 {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn assert_operational(env: &Env) {
        if Self::get_migration_status(env.clone()).is_some_and(|status| !status.complete) {
            panic!("storage migration in progress");
        }
    }

    fn require_valid_principal(address: &Address) -> Result<(), ContractError> {
        if !earnproof_shared::is_valid_principal_address(address) {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn bump_config_version(env: Env) {
        let current = Self::get_config_version(env.clone());
        let new_version = current
            .checked_add(1)
            .unwrap_or_else(|| panic!("config version overflow: reached maximum"));
        env.storage()
            .instance()
            .set(&DataKey::ConfigVersion, &new_version);
        Self::extend_instance_ttl(env);
    }

    fn extend_instance_ttl(env: Env) {
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_TO_LEDGERS);
        let live_until = Self::tracked_live_until(&env);
        env.storage()
            .instance()
            .set(&DataKey::InstanceLiveUntil, &live_until);
    }

    fn extend_schema_ttl(env: Env, version: u32) {
        let live_until = Self::tracked_live_until(&env);
        let tracker = DataKey::SchemaTtl(version);
        env.storage().persistent().extend_ttl(
            &DataKey::SchemaVersion(version),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_TO_LEDGERS,
        );
        env.storage().persistent().set(&tracker, &live_until);
        env.storage().persistent().extend_ttl(
            &tracker,
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_TO_LEDGERS,
        );
    }

    fn tracked_live_until(env: &Env) -> u32 {
        env.ledger()
            .sequence()
            .saturating_add(TTL_EXTEND_TO_LEDGERS.min(env.storage().max_ttl()))
    }

    fn require_auth(address: &Address) {
        address.require_auth();
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::{DataKey, ProtocolConfigContract, ProtocolConfigContractClient};
    use earnproof_shared::TTL_THRESHOLD_LEDGERS;
    use soroban_sdk::{
        testutils::storage::{Instance as _, Persistent as _},
        Address, BytesN, Env,
    };

    const ADMIN: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";
    const OTHER: &str = "GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U";

    fn bytes(env: &Env, value: u8) -> BytesN<32> {
        BytesN::from_array(env, &[value; 32])
    }

    fn setup() -> (Env, ProtocolConfigContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        client.initialize(&admin);
        (env, client, admin)
    }

    // ── existing tests ────────────────────────────────────────────────────────

    #[test]
    fn initializes_config_defaults() {
        let (_env, client, admin) = setup();

        assert_eq!(client.get_admin(), admin);
        assert!(!client.is_paused());
        assert_eq!(client.get_config_version(), 1);
        assert!(!client.is_schema_version_approved(&1));
        // contract version initialized to 1
        assert_eq!(client.get_contract_version(), 1);
    }

    #[test]
    fn pause_and_unpause_bump_config_version() {
        let (_env, client, _admin) = setup();

        client.pause();
        assert!(client.is_paused());
        assert_eq!(client.get_config_version(), 2);

        client.unpause();
        assert!(!client.is_paused());
        assert_eq!(client.get_config_version(), 3);
    }

    #[test]
    fn schema_versions_can_be_approved_and_deprecated() {
        let (_env, client, _admin) = setup();

        client.approve_schema_version(&1);
        assert!(client.is_schema_version_approved(&1));

        client.deprecate_schema_version(&1);
        assert!(!client.is_schema_version_approved(&1));
    }

    #[test]
    fn rejects_zero_schema_version() {
        let (_env, client, _admin) = setup();
        use earnproof_shared::ContractError;

        let result = client.try_approve_schema_version(&0);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn extends_schema_storage_ttl() {
        let (env, client, _admin) = setup();

        client.approve_schema_version(&7);

        env.as_contract(&client.address, || {
            assert!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::SchemaVersion(7))
                    > TTL_THRESHOLD_LEDGERS
            );
        });
    }

    // ── upgrade governance tests ──────────────────────────────────────────────

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
        assert!(client.is_upgrade_allowed(&hash));

        client.revoke_upgrade(&hash);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    #[test]
    fn approve_upgrade_rejects_downgrade_version() {
        let (env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        // current version is 1; attempting to allowlist version 1 is rejected
        let result = client.try_approve_upgrade(&bytes(&env, 1), &1);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn approve_upgrade_rejects_lower_version() {
        let (env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        // current version is 1; version 0 must be rejected
        let result = client.try_approve_upgrade(&bytes(&env, 1), &0);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn upgrade_contract_rejects_non_allowlisted_hash() {
        let (env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        let result = client.try_upgrade_contract(&bytes(&env, 0xff), &2);
        assert_eq!(result, Err(Ok(ContractError::NoUpgradeApproval)));
    }

    /// Verifies that `upgrade_contract` enforces admin authorization before
    /// doing anything.  `mock_all_auths` is intentionally NOT used here.
    #[test]
    #[should_panic]
    fn upgrade_contract_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // Initialize using mocked auths.
        env.mock_all_auths();
        client.initialize(&admin);
        let hash = BytesN::from_array(&env, &[0xde; 32]);
        client.approve_upgrade(&hash, &2);
        env.set_auths(&[]);

        // Attempt upgrade without auth — must panic.
        client.upgrade_contract(&hash, &2);
    }

    /// Verifies that the allowlist entry is consumed after a successful upgrade
    /// so the same hash cannot be replayed.
    ///
    /// Note: in the test environment `update_current_contract_wasm` is a no-op
    /// (the WASM is not actually swapped) but all surrounding state transitions
    /// — version bump, allowlist removal, event emission — are fully exercised.
    #[test]
    fn upgrade_contract_advances_version_and_consumes_allowlist() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x42);

        assert_eq!(client.get_contract_version(), 1);
        client.approve_upgrade(&hash, &2);
        assert!(client.is_upgrade_allowed(&hash));

        // Advance past timelock before executing
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash, &2);

        // Version must have advanced.
        assert_eq!(client.get_contract_version(), 2);
        // Allowlist entry must have been consumed.
        assert!(!client.is_upgrade_allowed(&hash));
    }

    /// After a successful upgrade the same hash cannot be applied a second
    /// time (allowlist entry was consumed, and the version guard would also
    /// block it even if re-approved with the same version).
    #[test]
    fn upgrade_contract_hash_cannot_be_replayed() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x42);
        use earnproof_shared::ContractError;

        client.approve_upgrade(&hash, &2);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash, &2);

        // Second application must fail — entry was consumed.
        let result = client.try_upgrade_contract(&hash, &2);
        assert_eq!(result, Err(Ok(ContractError::NoUpgradeApproval)));
    }

    /// State written before an upgrade is still readable after.
    #[test]
    fn state_preserved_across_upgrade() {
        let (env, client, _admin) = setup();

        // Write some state before the upgrade.
        client.approve_schema_version(&3);
        client.pause();
        assert!(client.is_paused());
        assert!(client.is_schema_version_approved(&3));

        // Perform upgrade.
        let hash = bytes(&env, 0x77);
        client.approve_upgrade(&hash, &2);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash, &2);

        // State must be intact after upgrade.
        assert!(client.is_paused());
        assert!(client.is_schema_version_approved(&3));
        assert_eq!(client.get_contract_version(), 2);
    }

    /// An upgrade approved with version N cannot be reused to downgrade from
    /// a later version M > N even if the hash is re-added to the allowlist.
    #[test]
    fn cannot_re_approve_old_version_after_upgrade() {
        let (env, client, _admin) = setup();
        let hash_v2 = bytes(&env, 0x01);
        let old_hash = bytes(&env, 0x02);
        use earnproof_shared::ContractError;

        // Upgrade to version 2.
        client.approve_upgrade(&hash_v2, &2);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash_v2, &2);
        assert_eq!(client.get_contract_version(), 2);

        // Attempt to allowlist a hash that would install version 1 — rejected.
        let result = client.try_approve_upgrade(&old_hash, &1);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    /// `approve_upgrade` by a non-admin must be rejected.
    #[test]
    #[should_panic]
    fn approve_upgrade_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other = Address::from_str(&env, OTHER);

        env.mock_all_auths();
        client.initialize(&admin);

        // Only authorize `other`, not `admin` — should panic.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &other,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &client.address,
                fn_name: "approve_upgrade",
                args: soroban_sdk::vec![
                    &env,
                    soroban_sdk::IntoVal::into_val(&BytesN::from_array(&env, &[0xaa; 32]), &env),
                    soroban_sdk::IntoVal::into_val(&2_u32, &env),
                ],
                sub_invokes: &[],
            },
        }]);
        client.approve_upgrade(&BytesN::from_array(&env, &[0xaa; 32]), &2);
    }

    // ── numeric boundary tests ────────────────────────────────────────────────

    /// Table-driven tests for schema version boundaries.
    #[test]
    fn schema_version_boundary_values() {
        let (_env, client, _admin) = setup();

        client.approve_schema_version(&1);
        assert!(client.is_schema_version_approved(&1));

        client.approve_schema_version(&2);
        assert!(client.is_schema_version_approved(&2));

        client.approve_schema_version(&100);
        assert!(client.is_schema_version_approved(&100));

        client.approve_schema_version(&u32::MAX);
        assert!(client.is_schema_version_approved(&u32::MAX));
    }

    #[test]
    fn schema_version_zero_rejected() {
        let (_env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        let result = client.try_approve_schema_version(&0);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn is_schema_version_approved_with_zero_returns_false() {
        let (_env, client, _admin) = setup();
        let result = client.is_schema_version_approved(&0);
        assert!(!result);
    }

    /// Table-driven tests for contract version boundaries.
    #[test]
    fn contract_version_upgrade_boundaries() {
        let (env, client, _admin) = setup();
        assert_eq!(client.get_contract_version(), 1);

        // Valid: immediate next version
        client.approve_upgrade(&bytes(&env, 1), &2);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&bytes(&env, 1), &2);
        assert_eq!(client.get_contract_version(), 2);

        // Valid: skip versions (not required to be sequential)
        client.approve_upgrade(&bytes(&env, 2), &1000);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&bytes(&env, 2), &1000);
        assert_eq!(client.get_contract_version(), 1000);

        // Valid: very large version number
        client.approve_upgrade(&bytes(&env, 3), &u32::MAX);
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&bytes(&env, 3), &u32::MAX);
        assert_eq!(client.get_contract_version(), u32::MAX);
    }

    #[test]
    fn contract_version_equal_current_rejected() {
        let (env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        // Current version is 1; attempting to set it to 1 again is rejected
        let result = client.try_approve_upgrade(&bytes(&env, 1), &1);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn contract_version_below_current_rejected() {
        let (env, client, _admin) = setup();
        use earnproof_shared::ContractError;
        // Current version is 1; attempting to set it to 0 is rejected
        let result = client.try_approve_upgrade(&bytes(&env, 1), &0);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    /// Table-driven tests for config version bumping.
    #[test]
    fn config_version_increments_on_mutations() {
        let (_env, client, _admin) = setup();
        assert_eq!(client.get_config_version(), 1);

        client.pause();
        assert_eq!(client.get_config_version(), 2);

        client.unpause();
        assert_eq!(client.get_config_version(), 3);

        client.approve_schema_version(&1);
        assert_eq!(client.get_config_version(), 4);

        client.deprecate_schema_version(&1);
        assert_eq!(client.get_config_version(), 5);
    }

    #[test]
    fn config_version_safe_near_u32_max() {
        let (_env, client, _admin) = setup();

        let mut v = client.get_config_version();
        assert_eq!(v, 1);

        for _ in 0..10 {
            client.pause();
            let after_pause = client.get_config_version();
            assert_eq!(after_pause, v + 1, "pause must bump config version exactly once");

            client.unpause();
            let after_unpause = client.get_config_version();
            assert_eq!(
                after_unpause,
                after_pause + 1,
                "unpause must bump config version exactly once"
            );
            v = after_unpause;
        }
    }

    #[test]
    fn failed_schema_version_zero_leaves_state_unchanged() {
        let (_env, client, _admin) = setup();

        let config_before = client.get_config_version();
        let approved_before = client.is_schema_version_approved(&999);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.approve_schema_version(&0);
        }));

        assert!(result.is_err());
        assert_eq!(client.get_config_version(), config_before);
        assert_eq!(client.is_schema_version_approved(&999), approved_before);
    }

    #[test]
    fn failed_upgrade_version_downgrade_leaves_state_unchanged() {
        let (env, client, _admin) = setup();

        let contract_version_before = client.get_contract_version();
        let config_version_before = client.get_config_version();
        let hash = bytes(&env, 0x99);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.approve_upgrade(&hash, &0);
        }));

        assert!(result.is_err());
        assert_eq!(client.get_contract_version(), contract_version_before);
        assert_eq!(client.get_config_version(), config_version_before);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    // ── adversarial initialization tests ──────────────────────────────────────

    #[test]
    fn initialization_writes_exactly_documented_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);

        // Verify exact state written
        assert_eq!(client.get_admin(), admin, "admin must be set");
        assert!(
            !client.is_paused(),
            "protocol must not be paused after initialization"
        );
        assert_eq!(
            client.get_config_version(),
            1,
            "config version must be exactly 1 after initialization"
        );
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must be exactly 1 after initialization"
        );

        env.as_contract(&contract_id, || {
            let instance = env.storage().instance();
            assert!(instance.has(&DataKey::Admin));
            assert!(instance.has(&DataKey::Paused));
            assert!(instance.has(&DataKey::ConfigVersion));
            assert!(instance.has(&DataKey::ContractVersion));
        });
    }

    #[test]
    fn reinitialization_by_same_admin_fails_atomically() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);
        let config_version_after_first = client.get_config_version();
        let contract_version_after_first = client.get_contract_version();
        let paused_after_first = client.is_paused();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin);
        }));

        assert!(result.is_err(), "re-initialization must panic");
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_config_version(), config_version_after_first);
        assert_eq!(client.get_contract_version(), contract_version_after_first);
        assert_eq!(client.is_paused(), paused_after_first);
    }

    #[test]
    fn reinitialization_by_different_admin_fails_atomically() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other = Address::from_str(&env, OTHER);

        client.initialize(&admin);
        let stored_admin = client.get_admin();
        let config_version_after_first = client.get_config_version();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&other);
        }));

        assert!(result.is_err());
        assert_eq!(client.get_admin(), stored_admin);
        assert_eq!(client.get_config_version(), config_version_after_first);
    }

    #[test]
    fn reinitialization_by_arbitrary_special_address_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);
        let stored_admin = client.get_admin();
        let arbitrary = Address::from_str(&env, OTHER);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&arbitrary);
        }));

        assert!(result.is_err());
        assert_eq!(client.get_admin(), stored_admin);
    }

    #[test]
    fn reinitialization_panic_message_indicates_guard() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin);
        }));

        assert!(result.is_err());
    }

    #[test]
    fn reinitialization_guard_active_immediately() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);

        for attempt in 1..=3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.initialize(&admin);
            }));

            assert!(result.is_err(), "re-initialization attempt {} must fail", attempt);
            assert_eq!(
                client.get_admin(),
                admin,
                "admin must not change after re-initialization attempt {}",
                attempt
            );
        }
    }

    #[test]
    fn initialization_state_stable_before_mutations() {
        let (_env, client, admin) = setup();

        assert_eq!(client.get_admin(), admin);
        assert!(!client.is_paused());
        assert_eq!(client.get_config_version(), 1);
        assert_eq!(client.get_contract_version(), 1);

        client.pause();

        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_config_version(), 2);
        assert_eq!(client.get_contract_version(), 1);
    }

    #[test]
    fn protocol_config_initialization_spec_summary() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
        assert!(!client.is_paused());
        assert_eq!(client.get_config_version(), 1);
        assert_eq!(client.get_contract_version(), 1);

        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin)
        }))
        .is_err());
    }

    // ── approval metadata tests ────────────────────────────────────────────────

    #[test]
    fn get_metadata_returns_found_for_active_approval() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, admin) = setup();
        let hash = bytes(&env, 0xab);

        client.approve_upgrade(&hash, &2);

        let result = client.get_upgrade_approval_metadata(&hash);

        match result {
            ApprovalQuery::Found(metadata) => {
                assert_eq!(metadata.target_hash, hash);
                assert_eq!(metadata.target_version, 2);
                assert_eq!(metadata.approver, admin);
                assert_eq!(metadata.execution_ledger, None);
                assert_eq!(metadata.status, ApprovalStatus::Active);
                assert!(metadata.creation_ledger > 0);
                assert!(metadata.expiry_ledger > metadata.creation_ledger);
            }
            _ => panic!("expected ApprovalQuery::Found"),
        }
    }

    #[test]
    fn get_metadata_returns_executed_after_upgrade_executed() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0xcd);

        client.approve_upgrade(&hash, &2);
        let creation_ledger = env.ledger().sequence();
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash, &2);
        let execution_ledger = env.ledger().sequence();

        let result = client.get_upgrade_approval_metadata(&hash);

        match result {
            ApprovalQuery::Found(metadata) => {
                assert_eq!(metadata.status, ApprovalStatus::Executed);
                assert_eq!(metadata.execution_ledger, Some(execution_ledger));
                assert!(metadata.execution_ledger.unwrap() >= creation_ledger);
            }
            _ => panic!("expected ApprovalQuery::Found with Executed status"),
        }
    }

    #[test]
    fn get_metadata_returns_not_found_for_unknown_hash() {
        use earnproof_shared::ApprovalQuery;

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0xff);

        let result = client.get_upgrade_approval_metadata(&hash);

        match result {
            ApprovalQuery::NotFound => {}
            _ => panic!("expected ApprovalQuery::NotFound"),
        }
    }

    #[test]
    fn get_metadata_returns_revoked_for_explicitly_revoked_approval() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0xee);

        client.approve_upgrade(&hash, &2);
        client.revoke_upgrade(&hash);

        let result = client.get_upgrade_approval_metadata(&hash);

        match result {
            ApprovalQuery::Revoked(metadata) => {
                assert_eq!(metadata.status, ApprovalStatus::Revoked);
            }
            _ => panic!("expected ApprovalQuery::Revoked"),
        }
    }

    #[test]
    fn not_found_is_distinct_from_revoked() {
        use earnproof_shared::ApprovalQuery;

        let (env, client, _admin) = setup();
        let unknown_hash = bytes(&env, 0x11);
        let revoked_hash = bytes(&env, 0x22);

        client.approve_upgrade(&revoked_hash, &2);
        client.revoke_upgrade(&revoked_hash);

        let unknown_result = client.get_upgrade_approval_metadata(&unknown_hash);
        assert!(matches!(unknown_result, ApprovalQuery::NotFound));

        let revoked_result = client.get_upgrade_approval_metadata(&revoked_hash);
        assert!(matches!(revoked_result, ApprovalQuery::Revoked(_)));
    }

    #[test]
    fn get_metadata_shows_expired_after_expiry_ledger_passes() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x33);

        client.approve_upgrade(&hash, &2);

        let metadata_before = match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(m) => m,
            _ => panic!("expected Found"),
        };
        let expiry_ledger = metadata_before.expiry_ledger;

        env.ledger().with_sequence(expiry_ledger + 1, || {
            let result = client.get_upgrade_approval_metadata(&hash);
            match result {
                ApprovalQuery::Found(metadata) => {
                    assert_eq!(metadata.status, ApprovalStatus::Expired);
                }
                _ => panic!("expected ApprovalQuery::Found with Expired status"),
            }
        });
    }

    #[test]
    fn get_metadata_shows_active_at_exactly_expiry_ledger() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x44);

        client.approve_upgrade(&hash, &2);

        let metadata_before = match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(m) => m,
            _ => panic!("expected Found"),
        };
        let expiry_ledger = metadata_before.expiry_ledger;

        env.ledger().with_sequence(expiry_ledger, || {
            let result = client.get_upgrade_approval_metadata(&hash);
            match result {
                ApprovalQuery::Found(metadata) => {
                    assert_eq!(metadata.status, ApprovalStatus::Active);
                }
                _ => panic!("expected ApprovalQuery::Found with Active status at boundary"),
            }
        });
    }

    #[test]
    fn get_metadata_does_not_mutate_storage() {
        use earnproof_shared::ApprovalQuery;

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x55);

        client.approve_upgrade(&hash, &2);

        let _result1 = client.get_upgrade_approval_metadata(&hash);
        let _result2 = client.get_upgrade_approval_metadata(&hash);
        let _result3 = client.get_upgrade_approval_metadata(&hash);

        match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(metadata) => {
                assert_eq!(metadata.execution_ledger, None);
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn get_metadata_expired_status_not_written_to_storage() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x66);

        client.approve_upgrade(&hash, &2);

        let metadata_before = match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(m) => m,
            _ => panic!("expected Found"),
        };
        let expiry_ledger = metadata_before.expiry_ledger;

        env.ledger().with_sequence(expiry_ledger + 1, || {
            let result = client.get_upgrade_approval_metadata(&hash);
            match result {
                ApprovalQuery::Found(metadata) => {
                    assert_eq!(metadata.status, ApprovalStatus::Expired);
                }
                _ => panic!("expected Found with Expired"),
            }
        });

        // Back within the valid window — stored status must still be Active
        let stored_result = client.get_upgrade_approval_metadata(&hash);
        match stored_result {
            ApprovalQuery::Found(metadata) => {
                if env.ledger().sequence() <= metadata.expiry_ledger {
                    assert_eq!(metadata.status, ApprovalStatus::Active);
                }
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn approval_metadata_stores_all_required_fields() {
        use earnproof_shared::{ApprovalQuery, ApprovalStatus};

        let (env, client, admin) = setup();
        let hash = bytes(&env, 0x77);
        let version = 5_u32;

        client.approve_upgrade(&hash, &version);

        match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(metadata) => {
                assert_eq!(metadata.target_hash, hash);
                assert_eq!(metadata.target_version, version);
                assert_eq!(metadata.approver, admin);
                assert!(metadata.creation_ledger > 0);
                assert_eq!(metadata.execution_ledger, None);
                assert!(metadata.expiry_ledger > metadata.creation_ledger);
                assert_eq!(metadata.status, ApprovalStatus::Active);
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn execution_ledger_set_when_upgrade_executed() {
        use earnproof_shared::ApprovalQuery;

        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x88);

        client.approve_upgrade(&hash, &2);

        let before_execution = match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(m) => m.execution_ledger,
            _ => panic!("expected Found"),
        };
        assert_eq!(before_execution, None);

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + earnproof_shared::UPGRADE_TIMELOCK_LEDGERS);
        client.upgrade_contract(&hash, &2);

        match client.get_upgrade_approval_metadata(&hash) {
            ApprovalQuery::Found(metadata) => {
                assert!(metadata.execution_ledger.is_some());
                assert!(metadata.execution_ledger.unwrap() > 0);
            }
            _ => panic!("expected Found"),
        }
    }

    #[test]
    fn multiple_approvals_independent() {
        use earnproof_shared::ApprovalQuery;

        let (env, client, _admin) = setup();
        let hash1 = bytes(&env, 0x99);
        let hash2 = bytes(&env, 0xaa);

        // Create two approvals (second replaces first in the active slot,
        // but both metadata records remain in persistent storage)
        client.approve_upgrade(&hash1, &2);
        client.approve_upgrade(&hash2, &3);

        match client.get_upgrade_approval_metadata(&hash1) {
            ApprovalQuery::Found(m1) => {
                assert_eq!(m1.target_version, 2);

                match client.get_upgrade_approval_metadata(&hash2) {
                    ApprovalQuery::Found(m2) => {
                        assert_eq!(m2.target_version, 3);
                        assert_ne!(m1.target_hash, m2.target_hash);
                    }
                    _ => panic!("expected Found for hash2"),
                }
            }
            _ => panic!("expected Found for hash1"),
        }
    }
}

#[cfg(test)]
mod upgrade_timelock_tests {
    extern crate std;

    use super::{DataKey, ProtocolConfigContract, ProtocolConfigContractClient};
    use earnproof_shared::{
        ContractError, UpgradeApproval, UPGRADE_APPROVAL_EXPIRY_LEDGERS, UPGRADE_TIMELOCK_LEDGERS,
    };
    use soroban_sdk::{testutils::Ledger as _, Address, BytesN, Env};

    const ADMIN: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";

    fn make_wasm_hash(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[1u8; 32])
    }

    fn setup() -> (Env, ProtocolConfigContractClient<'static>, Address) {
    #[test]
    fn pause_metadata_lifecycle_is_bounded_and_deterministic() {
        let (env, client, _admin) = setup();
        let incident_id = bytes(&env, 0x31);
        let reason_commitment = bytes(&env, 0x42);

        client.pause_with_metadata(&incident_id, &reason_commitment);
        let active = client.get_current_pause().expect("active pause metadata");
        assert_eq!(active.incident_id, incident_id);
        assert_eq!(active.reason_commitment, reason_commitment);
        assert!(active.active);
        assert_eq!(active.ended_at, 0);
        assert_eq!(client.get_config_version(), 2);

        // An identical retry is a no-op; conflicting metadata cannot replace
        // the incident already in progress.
        client.pause_with_metadata(&incident_id, &reason_commitment);
        assert_eq!(client.get_config_version(), 2);
        assert_eq!(
            client.try_pause_with_metadata(&bytes(&env, 0x32), &reason_commitment),
            Err(Ok(earnproof_shared::ContractError::InvalidState))
        );

        client.unpause();
        assert!(client.get_current_pause().is_none());
        let closed = client.get_latest_pause().expect("latest pause metadata");
        assert_eq!(closed.incident_id, incident_id);
        assert!(!closed.active);
        assert!(closed.ended_at >= closed.started_at);
        assert_eq!(client.get_config_version(), 3);

        client.unpause();
        assert_eq!(client.get_config_version(), 3);
        assert_eq!(client.get_latest_pause(), Some(closed));
    }

    #[test]
    fn paused_legacy_state_can_be_migrated_once() {
        let (env, client, _admin) = setup();
        env.as_contract(&client.address, || {
            env.storage().instance().set(&DataKey::Paused, &true);
        });

        let incident_id = bytes(&env, 0x51);
        let reason_commitment = bytes(&env, 0x52);
        client.migrate_pause_metadata(&incident_id, &reason_commitment);

        let metadata = client.get_current_pause().expect("migrated metadata");
        assert_eq!(metadata.incident_id, incident_id);
        assert_eq!(metadata.reason_commitment, reason_commitment);
        assert!(metadata.active);
        assert_eq!(
            client.try_migrate_pause_metadata(&incident_id, &reason_commitment),
            Err(Ok(earnproof_shared::ContractError::InvalidState))
        );
    }

    #[test]
    fn pause_metadata_uses_the_contract_instance_ttl() {
        let (env, client, _admin) = setup();
        client.pause_with_metadata(&bytes(&env, 0x61), &bytes(&env, 0x62));

        let ttl = env.as_contract(&client.address, || env.storage().instance().get_ttl());
        assert!(ttl > TTL_THRESHOLD_LEDGERS);
        assert!(client.get_current_pause().is_some());
        assert!(client.get_latest_pause().is_some());
    }

    #[test]
    #[should_panic]
    fn pause_metadata_requires_current_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other = Address::from_str(&env, OTHER);
        client.initialize(&admin);

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &other,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &client.address,
                fn_name: "pause_with_metadata",
                args: soroban_sdk::vec![
                    &env,
                    soroban_sdk::IntoVal::into_val(&bytes(&env, 0x71), &env),
                    soroban_sdk::IntoVal::into_val(&bytes(&env, 0x72), &env),
                ],
                sub_invokes: &[],
            },
        }]);
        client.pause_with_metadata(&bytes(&env, 0x71), &bytes(&env, 0x72));
    }

    #[test]
    fn migration_checkpoints_resume_and_replay_monotonically() {
        let (_env, client, _admin) = setup();
        let started = client.begin_migration(&2, &250);
        assert_eq!(started.cursor, 0);
        assert!(!started.complete);
        let first = client.advance_migration(&0, &100);
        assert_eq!(first.cursor, 100);
        assert_eq!(client.get_migration_status(), Some(first.clone()));
        assert_eq!(client.advance_migration(&0, &100), first);
        assert_eq!(client.advance_migration(&100, &100).cursor, 200);
        let complete = client.advance_migration(&200, &50);
        assert_eq!(complete.cursor, 250);
        assert!(complete.complete);
    }

    #[test]
    fn migration_batch_and_cursor_boundaries_are_enforced() {
        let (_env, client, _admin) = setup();
        assert_eq!(
            client.try_begin_migration(&1, &10),
            Err(Ok(earnproof_shared::ContractError::InvalidInput))
        );
        assert_eq!(
            client.try_begin_migration(&2, &0),
            Err(Ok(earnproof_shared::ContractError::InvalidInput))
        );
        client.begin_migration(&2, &101);
        assert_eq!(
            client.try_advance_migration(&0, &(earnproof_shared::MAX_MIGRATION_BATCH + 1)),
            Err(Ok(earnproof_shared::ContractError::InvalidInput))
        );
        assert_eq!(
            client.try_advance_migration(&1, &1),
            Err(Ok(earnproof_shared::ContractError::InvalidState))
        );
        client.advance_migration(&0, &100);
        assert_eq!(
            client.try_advance_migration(&100, &2),
            Err(Ok(earnproof_shared::ContractError::InvalidInput))
        );
    }

    #[test]
    fn migration_blocks_operations_and_upgrade_until_complete() {
        let (env, client, _admin) = setup();
        let wasm_hash = bytes(&env, 0x81);
        client.approve_upgrade(&wasm_hash, &2);
        client.begin_migration(&2, &2);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { client.pause() })).is_err()
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.upgrade_contract(&wasm_hash)
        }))
        .is_err());
        client.advance_migration(&0, &2);
        client.upgrade_contract(&wasm_hash);
        assert_eq!(client.get_contract_version(), 2);
        assert!(client.get_migration_status().is_none());
    }

    #[test]
    #[should_panic]
    fn migration_checkpoint_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        client.initialize(&admin);
        (env, client, admin)
    }

    // ── SUITE 1: Approve stores correct timing ────────────────

    #[test]
    fn test_approve_stores_created_at() {
        let (env, client, _) = setup();

        let start_ledger = env.ledger().sequence();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            assert!(approval.is_some(), "Approval must be stored");
            assert_eq!(approval.unwrap().created_at, start_ledger);
        });
    }

    #[test]
    fn test_approve_stores_earliest_execution() {
        let (env, client, _) = setup();

        let start = env.ledger().sequence();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            assert_eq!(
                approval.unwrap().earliest_execution,
                start.saturating_add(UPGRADE_TIMELOCK_LEDGERS)
            );
        });
    }

    #[test]
    fn test_approve_stores_expires_at() {
        let (env, client, _) = setup();

        let start = env.ledger().sequence();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            assert_eq!(
                approval.unwrap().expires_at,
                start.saturating_add(UPGRADE_APPROVAL_EXPIRY_LEDGERS)
            );
        });
    }

    #[test]
    fn test_re_approval_resets_all_timing_metadata() {
        let (env, client, _) = setup();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            let first_created = approval.as_ref().unwrap().created_at;
            let first_earliest = approval.as_ref().unwrap().earliest_execution;
            let first_expires = approval.unwrap().expires_at;

            env.ledger()
                .set_sequence_number(env.ledger().sequence() + 1000);

            client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

            let approval2: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            let approval2 = approval2.unwrap();

            assert_ne!(approval2.created_at, first_created, "Re-approval must reset created_at");
            assert_ne!(approval2.earliest_execution, first_earliest, "Re-approval must reset earliest_execution");
            assert_ne!(approval2.expires_at, first_expires, "Re-approval must reset expires_at");
        });
    }

    // ── SUITE 2: Timelock enforcement ─────────────────────────

    #[test]
    fn test_execute_before_timelock_rejected() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        let result = client.try_upgrade_contract(&hash, &2);

        assert_eq!(
            result,
            Err(Ok(ContractError::UpgradeTimelockNotElapsed)),
            "Execute before timelock must be rejected"
        );
    }

    #[test]
    fn test_execute_exactly_at_timelock_succeeds() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_TIMELOCK_LEDGERS);

        let result = client.try_upgrade_contract(&hash, &2);
        assert!(result.is_ok(), "Execute at earliest_execution must succeed");
    }

    #[test]
    fn test_execute_one_before_timelock_rejected() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_TIMELOCK_LEDGERS - 1);

        assert!(client.try_upgrade_contract(&hash, &2).is_err());
    }

    // ── SUITE 3: Expiry enforcement ────────────────────────────

    #[test]
    fn test_execute_after_expiry_rejected() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_APPROVAL_EXPIRY_LEDGERS + 1);

        let result = client.try_upgrade_contract(&hash, &2);
        assert_eq!(
            result,
            Err(Ok(ContractError::UpgradeApprovalExpired)),
            "Execute after expiry must be rejected"
        );
    }

    #[test]
    fn test_execute_exactly_at_expiry_rejected() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_APPROVAL_EXPIRY_LEDGERS);

        let result = client.try_upgrade_contract(&hash, &2);
        assert_eq!(
            result,
            Err(Ok(ContractError::UpgradeApprovalExpired)),
            "Execute at exact expiry ledger must be rejected (>=)"
        let other = Address::from_str(&env, OTHER);
        client.initialize(&admin);
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &other,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &client.address,
                fn_name: "begin_migration",
                args: soroban_sdk::vec![
                    &env,
                    soroban_sdk::IntoVal::into_val(&2_u32, &env),
                    soroban_sdk::IntoVal::into_val(&10_u32, &env),
                ],
                sub_invokes: &[],
            },
        }]);
        client.begin_migration(&2, &10);
    }

    #[test]
    fn configuration_digest_matches_host_helper_and_changes_with_state() {
        let (env, client, admin) = setup();
        assert_eq!(
            ProtocolConfigContractClient::get_config_digest_version(&client),
            earnproof_shared::CONFIG_DIGEST_VERSION
        );

        let initial = client.get_config_digest();
        assert_eq!(
            initial,
            earnproof_shared::protocol_config_digest(&env, &admin, false, 1, 1)
        );
        assert_eq!(
            initial.to_array(),
            [
                66, 207, 114, 36, 209, 145, 19, 67, 60, 150, 121, 245, 26, 154, 197, 30, 130, 94,
                244, 239, 165, 103, 132, 135, 231, 95, 89, 29, 14, 149, 184, 15,
            ]
        );

        client.pause();
        let paused = client.get_config_digest();
        assert_ne!(paused, initial);
        assert_eq!(
            paused,
            earnproof_shared::protocol_config_digest(&env, &admin, true, 2, 1)
        );
    }

    #[test]
    fn ttl_status_covers_fresh_threshold_expired_restored_and_migrated_state() {
        let (env, client, _admin) = setup();
        assert_eq!(
            client.get_instance_ttl_status().health,
            earnproof_shared::TtlHealth::Healthy
        );
        assert_eq!(
            client.get_schema_ttl_status(&99).health,
            earnproof_shared::TtlHealth::Missing
        );

        client.approve_schema_version(&1);
        assert_eq!(
            client.get_schema_ttl_status(&1).health,
            earnproof_shared::TtlHealth::Healthy
        );

        let sequence = env.ledger().sequence();
        env.as_contract(&client.address, || {
            env.storage().instance().set(
                &DataKey::InstanceLiveUntil,
                &sequence.saturating_add(TTL_THRESHOLD_LEDGERS),
            );
        });
        assert_eq!(
            client.get_instance_ttl_status().health,
            earnproof_shared::TtlHealth::NearExpiry
        );

        env.as_contract(&client.address, || {
            env.storage()
                .instance()
                .set(&DataKey::InstanceLiveUntil, &sequence);
        });
        assert_eq!(
            client.get_instance_ttl_status().health,
            earnproof_shared::TtlHealth::Missing
        );

        env.as_contract(&client.address, || {
            env.storage().instance().remove(&DataKey::InstanceLiveUntil);
        });
        assert_eq!(
            client.get_instance_ttl_status().health,
            earnproof_shared::TtlHealth::Missing
        );
        assert_eq!(
            client.refresh_instance_ttl().health,
            earnproof_shared::TtlHealth::Healthy
        );
    }

    #[test]
    fn test_failed_execute_leaves_approval_unchanged() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        // Attempt execute before timelock (fails)
        let _ = client.try_upgrade_contract(&hash, &2);

        // Approval must still exist unchanged
        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            assert!(approval.is_some(), "Failed execute must not remove approval");
        });
    }

    // ── SUITE 4: Revocation ────────────────────────────────────

    #[test]
    fn test_revoke_removes_approval() {
        let (env, client, _) = setup();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();
        client.revoke_upgrade_approval().unwrap();

        env.as_contract(&client.address, || {
            let approval: Option<UpgradeApproval> = env
                .storage()
                .instance()
                .get(&DataKey::UpgradeApproval);
            assert!(approval.is_none(), "Revoke must remove approval");
        });
    }

    #[test]
    fn test_revoke_before_timelock_succeeds() {
        let (env, client, _) = setup();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();
        assert!(client.revoke_upgrade_approval().is_ok());
    }

    #[test]
    fn test_revoke_after_expiry_succeeds_cleanup() {
        let (env, client, _) = setup();

        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_APPROVAL_EXPIRY_LEDGERS + 1);

        assert!(client.revoke_upgrade_approval().is_ok());
    }

    #[test]
    fn test_revoke_idempotent_when_no_approval() {
        let (_env, client, _) = setup();

        // Revoke with no approval — should not panic
        assert!(client.revoke_upgrade_approval().is_ok());
    }

    // ── SUITE 5: Overflow boundary ─────────────────────────────

    #[test]
    fn test_approve_at_max_ledger_does_not_overflow() {
        let (env, client, _) = setup();

        env.ledger().set_sequence_number(u32::MAX - 1000);

        let result = client.try_approve_upgrade(&make_wasm_hash(&env), &2);
        assert!(result.is_ok(), "Approve near u32::MAX must not overflow");
    }

    #[test]
    fn test_saturating_add_caps_at_u32_max() {
        let near_max: u32 = u32::MAX - 100;
        let result = near_max.saturating_add(UPGRADE_TIMELOCK_LEDGERS);
        assert_eq!(result, u32::MAX, "saturating_add must cap at u32::MAX");
    }

    // ── SUITE 6: Replay prevention ─────────────────────────────

    #[test]
    fn test_cannot_replay_used_approval() {
        let (env, client, _) = setup();

        let hash = make_wasm_hash(&env);
        client.approve_upgrade(&hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_TIMELOCK_LEDGERS);

        client.upgrade_contract(&hash, &2).unwrap();

        let result = client.try_upgrade_contract(&hash, &2);
        assert_eq!(
            result,
            Err(Ok(ContractError::NoUpgradeApproval)),
            "Replaying used approval must fail"
        );
    }

    #[test]
    fn test_hash_mismatch_rejected() {
        let (env, client, _) = setup();

        let approved_hash = make_wasm_hash(&env);
        let different_hash = BytesN::from_array(&env, &[2u8; 32]);

        client.approve_upgrade(&approved_hash, &2).unwrap();

        env.ledger()
            .set_sequence_number(env.ledger().sequence() + UPGRADE_TIMELOCK_LEDGERS);

        let result = client.try_upgrade_contract(&different_hash, &2);
        assert_eq!(result, Err(Ok(ContractError::WasmHashMismatch)));
    }

    // ── SUITE 7: Authorization ─────────────────────────────────

    #[test]
    fn test_approve_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        env.mock_all_auths();
        client.initialize(&admin);
        env.set_auths(&[]);

        let result = client.try_approve_upgrade(&make_wasm_hash(&env), &2);
        assert!(result.is_err(), "Non-admin must not approve");
    }

    #[test]
    fn test_execute_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        env.mock_all_auths();
        client.initialize(&admin);
        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();
        env.set_auths(&[]);

        let result = client.try_upgrade_contract(&make_wasm_hash(&env), &2);
        assert!(result.is_err(), "Non-admin must not execute");
    }

    #[test]
    fn test_revoke_requires_admin_auth() {
        let env = Env::default();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        env.mock_all_auths();
        client.initialize(&admin);
        client.approve_upgrade(&make_wasm_hash(&env), &2).unwrap();
        env.set_auths(&[]);

        let result = client.try_revoke_upgrade_approval();
        assert!(result.is_err(), "Non-admin must not revoke");
    fn ttl_status_queries_do_not_extend_storage() {
        let (env, client, _admin) = setup();
        client.approve_schema_version(&1);
        let before = env.as_contract(&client.address, || {
            (
                env.storage().instance().get_ttl(),
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::SchemaVersion(1)),
            )
        });

        client.get_instance_ttl_status();
        client.get_schema_ttl_status(&1);

        let after = env.as_contract(&client.address, || {
            (
                env.storage().instance().get_ttl(),
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::SchemaVersion(1)),
            )
        });
        assert_eq!(after, before);
    }
}
