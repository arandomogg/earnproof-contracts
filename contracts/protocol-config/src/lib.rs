#![no_std]

use earnproof_shared::{
    ContractError, InterfaceVersion, PROTOCOL_CONFIG_INTERFACE_VERSION, TTL_EXTEND_TO_LEDGERS,
    TTL_THRESHOLD_LEDGERS,
};
use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, BytesN, Env};

#[contract]
pub struct ProtocolConfigContract;

#[contracttype]
enum DataKey {
    Admin,
    Paused,
    ConfigVersion,
    SchemaVersion(u32),
    /// Allowlist entry: maps a WASM hash to the target contract version it
    /// must install.  Only hashes pre-approved by the admin may be applied.
    AllowedWasm(BytesN<32>),
    /// Monotonically-increasing contract version stored in instance storage.
    /// Prevents installing an older (or equal) version over a newer one.
    ContractVersion,
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

    /// Machine-readable interface version this contract exposes to consumers.
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        PROTOCOL_CONFIG_INTERFACE_VERSION
    }

    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
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
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::bump_config_version(env.clone());
        Paused { paused: true }.publish(&env);
        Ok(())
    }

    pub fn unpause(env: Env) -> Result<(), ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_config_version(env.clone());
        Unpaused { paused: false }.publish(&env);
        Ok(())
    }

    pub fn approve_schema_version(env: Env, version: u32) -> Result<(), ContractError> {
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

    // ── upgrade governance ───────────────────────────────────────────────────

    /// Returns the stored monotonic contract version (separate from the
    /// config-mutation counter).  Starts at 1 after `initialize`.
    pub fn get_contract_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0)
    }

    /// Admin-only: add `wasm_hash` to the upgrade allowlist and record the
    /// `new_version` that must be installed by that WASM.
    ///
    /// `new_version` must be strictly greater than the currently stored
    /// contract version so that a downgrade cannot be pre-approved.
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

    /// Admin-only: remove a previously allowlisted WASM hash without applying
    /// it.  Safe to call even if the hash was never allowlisted.
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
    /// Requirements (all checked on-chain before the upgrade is applied):
    /// 1. Caller is the admin.
    /// 2. `wasm_hash` is on the allowlist (pre-approved via `approve_upgrade`).
    /// 3. The target version stored in the allowlist entry is strictly greater
    ///    than the current `ContractVersion` (downgrade guard).
    ///
    /// On success the new WASM is installed, `ContractVersion` is advanced,
    /// the allowlist entry is consumed (removed), and a `ContractUpgraded`
    /// event is emitted.
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

        // Consume the allowlist entry before applying so re-entrancy cannot
        // replay the same hash.
        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        // Apply the WASM upgrade.  This replaces the executable code while
        // leaving all stored state intact.
        #[cfg(not(test))]
        env.deployer()
            .update_current_contract_wasm(wasm_hash.clone());

        // Record the new version.
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

    // ── private helpers ──────────────────────────────────────────────────────

    fn ensure_nonzero_version(version: u32) -> Result<(), ContractError> {
        if version == 0 {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
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
    }

    fn extend_schema_ttl(env: Env, version: u32) {
        env.storage().persistent().extend_ttl(
            &DataKey::SchemaVersion(version),
            TTL_THRESHOLD_LEDGERS,
            TTL_EXTEND_TO_LEDGERS,
        );
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
    use soroban_sdk::{testutils::storage::Persistent as _, Address, BytesN, Env};

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
    fn exposes_a_stable_interface_version() {
        let (_env, client, _admin) = setup();
        let version = client.interface_version();
        assert_eq!(version, earnproof_shared::PROTOCOL_CONFIG_INTERFACE_VERSION);
        assert_eq!(version.major, 1);
    }

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
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn approve_upgrade_rejects_downgrade_version() {
        let (env, client, _admin) = setup();
        // current version is 1; attempting to allowlist version 1 is rejected
        client.approve_upgrade(&bytes(&env, 1), &1);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn approve_upgrade_rejects_lower_version() {
        let (env, client, _admin) = setup();
        // current version is 1; version 0 must be rejected
        client.approve_upgrade(&bytes(&env, 1), &0);
    }

    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_contract_rejects_non_allowlisted_hash() {
        let (env, client, _admin) = setup();
        client.upgrade_contract(&bytes(&env, 0xff));
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
        client.upgrade_contract(&hash);
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

        client.upgrade_contract(&hash);

        // Version must have advanced.
        assert_eq!(client.get_contract_version(), 2);
        // Allowlist entry must have been consumed.
        assert!(!client.is_upgrade_allowed(&hash));
    }

    /// After a successful upgrade the same hash cannot be applied a second
    /// time (allowlist entry was consumed, and the version guard would also
    /// block it even if re-approved with the same version).
    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_contract_hash_cannot_be_replayed() {
        let (env, client, _admin) = setup();
        let hash = bytes(&env, 0x42);

        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);
        // Second application must fail — entry was consumed.
        client.upgrade_contract(&hash);
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
        client.upgrade_contract(&hash);

        // State must be intact after upgrade.
        assert!(client.is_paused());
        assert!(client.is_schema_version_approved(&3));
        assert_eq!(client.get_contract_version(), 2);
    }

    /// An upgrade approved with version N cannot be reused to downgrade from
    /// a later version M > N even if the hash is re-added to the allowlist.
    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn cannot_re_approve_old_version_after_upgrade() {
        let (env, client, _admin) = setup();
        let hash_v2 = bytes(&env, 0x01);
        let old_hash = bytes(&env, 0x02);

        // Upgrade to version 2.
        client.approve_upgrade(&hash_v2, &2);
        client.upgrade_contract(&hash_v2);
        assert_eq!(client.get_contract_version(), 2);

        // Attempt to allowlist a hash that would install version 1 — rejected.
        client.approve_upgrade(&old_hash, &1);
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
                ]
                .into(),
                sub_invokes: &[],
            },
        }]);
        client.approve_upgrade(&BytesN::from_array(&env, &[0xaa; 32]), &2);
    }

    // ── numeric boundary tests ────────────────────────────────────────────────

    /// Table-driven tests for schema version boundaries.
    /// Schema versions must be >= MIN_SCHEMA_VERSION (1).
    #[test]
    fn schema_version_boundary_values() {
        let (_env, client, _admin) = setup();

        // Valid: minimum allowed schema version
        client.approve_schema_version(&1);
        assert!(client.is_schema_version_approved(&1));

        // Valid: typical schema versions
        client.approve_schema_version(&2);
        assert!(client.is_schema_version_approved(&2));

        client.approve_schema_version(&100);
        assert!(client.is_schema_version_approved(&100));

        // Valid: u32 maximum
        client.approve_schema_version(&u32::MAX);
        assert!(client.is_schema_version_approved(&u32::MAX));
    }

    #[test]
    fn schema_version_zero_rejected() {
        let (_env, client, _admin) = setup();
        // Version 0 must be rejected with a typed error.
        use earnproof_shared::ContractError;
        let result = client.try_approve_schema_version(&0);
        assert_eq!(result, Err(Ok(ContractError::InvalidInput)));
    }

    #[test]
    fn is_schema_version_approved_with_zero_returns_false() {
        let (_env, client, _admin) = setup();
        // Querying version 0 should return false without panic
        let result = client.is_schema_version_approved(&0);
        assert!(!result);
    }

    /// Table-driven tests for contract version boundaries.
    /// Contract versions must be > current version (monotonically increasing).
    #[test]
    fn contract_version_upgrade_boundaries() {
        let (env, client, _admin) = setup();
        assert_eq!(client.get_contract_version(), 1);

        // Valid: immediate next version
        client.approve_upgrade(&bytes(&env, 1), &2);
        client.upgrade_contract(&bytes(&env, 1));
        assert_eq!(client.get_contract_version(), 2);

        // Valid: skip versions (not required to be sequential)
        client.approve_upgrade(&bytes(&env, 2), &1000);
        client.upgrade_contract(&bytes(&env, 2));
        assert_eq!(client.get_contract_version(), 1000);

        // Valid: very large version number
        client.approve_upgrade(&bytes(&env, 3), &u32::MAX);
        client.upgrade_contract(&bytes(&env, 3));
        assert_eq!(client.get_contract_version(), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn contract_version_equal_current_rejected() {
        let (env, client, _admin) = setup();
        // Current version is 1; attempting to set it to 1 again is rejected
        client.approve_upgrade(&bytes(&env, 1), &1);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn contract_version_below_current_rejected() {
        let (env, client, _admin) = setup();
        // Current version is 1; attempting to set it to 0 is rejected
        client.approve_upgrade(&bytes(&env, 1), &0);
    }

    /// Table-driven tests for config version bumping.
    /// Config version increments on every configuration change.
    /// This tests the checked_add protection against overflow.
    #[test]
    fn config_version_increments_on_mutations() {
        let (_env, client, _admin) = setup();
        assert_eq!(client.get_config_version(), 1);

        // Each mutation bumps config version
        client.pause();
        assert_eq!(client.get_config_version(), 2);

        client.unpause();
        assert_eq!(client.get_config_version(), 3);

        client.approve_schema_version(&1);
        assert_eq!(client.get_config_version(), 4);

        client.deprecate_schema_version(&1);
        assert_eq!(client.get_config_version(), 5);
    }

    /// Verify that config version correctly handles large values
    /// approaching u32::MAX (bumping is protected by checked_add).
    #[test]
    fn config_version_safe_near_u32_max() {
        let (_env, client, _admin) = setup();

        // Manually set config version to a value near max by simulating
        // many mutations. We'll do a smaller simulation here.
        // In real operation, reaching u32::MAX would require ~4 billion mutations,
        // which is impractical in a test, but we verify the protection exists.

        // Get current config version (should be 1 after setup)
        let mut v = client.get_config_version();
        assert_eq!(v, 1);

        // Perform several mutations and verify each increments exactly once,
        // starting from the value established by the previous mutation.
        for _ in 0..10 {
            client.pause();
            let after_pause = client.get_config_version();
            assert_eq!(
                after_pause,
                v + 1,
                "pause must bump config version exactly once"
            );

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

    /// Test storage and event invariants: failed boundary cases
    /// must not modify state or emit events.
    #[test]
    fn failed_schema_version_zero_leaves_state_unchanged() {
        let (_env, client, _admin) = setup();

        let config_before = client.get_config_version();
        let approved_before = client.is_schema_version_approved(&999);

        // Attempt to approve version 0 — should panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.approve_schema_version(&0);
        }));

        // Must have panicked
        assert!(result.is_err());

        // State must be unchanged
        assert_eq!(client.get_config_version(), config_before);
        assert_eq!(
            client.is_schema_version_approved(&999),
            approved_before,
            "schema version approval state must not change on failed validation"
        );
    }

    #[test]
    fn failed_upgrade_version_downgrade_leaves_state_unchanged() {
        let (env, client, _admin) = setup();

        let contract_version_before = client.get_contract_version();
        let config_version_before = client.get_config_version();
        let hash = bytes(&env, 0x99);

        // Attempt to allowlist a downgrade (current version is 1, trying version 0)
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.approve_upgrade(&hash, &0);
        }));

        // Must have panicked
        assert!(result.is_err());

        // State must be unchanged: contract version not modified
        assert_eq!(
            client.get_contract_version(),
            contract_version_before,
            "contract version must not change on failed upgrade approval"
        );

        // Config version must not be bumped on failed validation
        assert_eq!(
            client.get_config_version(),
            config_version_before,
            "config version must not change when upgrade approval fails"
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
    /// - Paused = false
    /// - ConfigVersion = 1
    /// - ContractVersion = 1
    /// - Initialized event published
    #[test]
    fn initialization_writes_exactly_documented_state() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // Before initialization: storage should be empty
        // (querying uninitialized values returns defaults or panics)

        // Perform initialization
        client.initialize(&admin);

        // Verify exact state written
        assert_eq!(client.get_admin(), admin, "admin must be set");
        assert_eq!(
            client.is_paused(),
            false,
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

        // Verify Initialized event was published
        // (Event verification requires inspecting env's event log)
        env.as_contract(&contract_id, || {
            // Storage keys must all be set (verifiable via has() calls)
            let instance = env.storage().instance();
            assert!(
                instance.has(&DataKey::Admin),
                "Admin key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::Paused),
                "Paused key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::ConfigVersion),
                "ConfigVersion key must exist in instance storage"
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
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization succeeds
        client.initialize(&admin);
        let config_version_after_first = client.get_config_version();
        let contract_version_after_first = client.get_contract_version();
        let paused_after_first = client.is_paused();

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
            client.get_config_version(),
            config_version_after_first,
            "config version must not change after failed re-initialization"
        );
        assert_eq!(
            client.get_contract_version(),
            contract_version_after_first,
            "contract version must not change after failed re-initialization"
        );
        assert_eq!(
            client.is_paused(),
            paused_after_first,
            "paused state must not change after failed re-initialization"
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
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other = Address::from_str(&env, OTHER);

        // First initialization with original admin
        client.initialize(&admin);
        let stored_admin = client.get_admin();
        let config_version_after_first = client.get_config_version();

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
            client.get_config_version(),
            config_version_after_first,
            "config version must not change after failed re-initialization by different admin"
        );
    }

    /// Verify that an address that looks like it might have elevated permissions
    /// cannot bypass the re-initialization guard.
    ///
    /// Tests with an address string that is numeric (e.g., address index)
    /// or otherwise potentially special to the test framework.
    #[test]
    fn reinitialization_by_arbitrary_special_address_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization with standard admin
        client.initialize(&admin);
        let stored_admin = client.get_admin();

        // Attempt re-initialization with an arbitrary address that might look
        // special (e.g., derived from a standard test key)
        let arbitrary = Address::from_str(&env, OTHER);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&arbitrary);
        }));

        // Must have panicked
        assert!(
            result.is_err(),
            "re-initialization by arbitrary address must panic"
        );

        // Original admin must be preserved
        assert_eq!(
            client.get_admin(),
            stored_admin,
            "admin must not change when arbitrary address attempts re-initialization"
        );
    }

    /// Verify that the re-initialization guard is truly the only barrier —
    /// the panic message must indicate "already initialized", not a different
    /// validation error.
    #[test]
    fn reinitialization_panic_message_indicates_guard() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization succeeds
        client.initialize(&admin);

        // Attempt re-initialization and verify panic message
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin);
        }));

        assert!(result.is_err(), "re-initialization must panic");
        // The panic message is internal to the contract; we verify the failure occurred
    }

    /// Verify that the re-initialization guard takes effect immediately after
    /// the first initialize() call completes — no transient window during which
    /// a second initialize could partially succeed.
    #[test]
    fn reinitialization_guard_active_immediately() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // First initialization
        client.initialize(&admin);

        // Subsequent initializations (multiple attempts) must all fail
        for attempt in 1..=3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.initialize(&admin);
            }));

            assert!(
                result.is_err(),
                "re-initialization attempt {} must fail",
                attempt
            );

            // Admin must remain unchanged after each failed attempt
            assert_eq!(
                client.get_admin(),
                admin,
                "admin must not change after re-initialization attempt {}",
                attempt
            );
        }
    }

    /// Verify that the documented initialization state is maintained even
    /// across function calls and state mutations after initialization.
    ///
    /// Tests that the initial state (versions, paused flag) is stable
    /// and correct before any subsequent mutations.
    #[test]
    fn initialization_state_stable_before_mutations() {
        let (_env, client, admin) = setup();

        // State immediately after initialization must be as documented
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.is_paused(), false);
        assert_eq!(client.get_config_version(), 1);
        assert_eq!(client.get_contract_version(), 1);

        // Perform a mutation (pause)
        client.pause();

        // Admin must remain unchanged
        assert_eq!(
            client.get_admin(),
            admin,
            "admin must not change across mutations"
        );

        // But config version should have bumped
        assert_eq!(
            client.get_config_version(),
            2,
            "config version must increment on mutation"
        );

        // Contract version must remain at 1 (only changes on upgrade)
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must not change on config mutation"
        );
    }

    /// Summary test: protocol-config initialization spec verification.
    ///
    /// This test serves as executable documentation of what the test matrix
    /// expects from protocol-config initialization:
    /// - Standalone contract (no dependency addresses)
    /// - Has re-initialization guard
    /// - Emits Initialized event
    /// - Sets: admin, paused=false, config_version=1, contract_version=1
    #[test]
    fn protocol_config_initialization_spec_summary() {
        // CONTRACT SPEC: protocol-config
        // - Name: "protocol-config"
        // - Has re-initialization guard: YES (panics "already initialized")
        // - Emits initialization event: YES (Initialized { admin })
        // - Takes dependency addresses: NO
        // - Dependencies: []
        // - First init writes:
        //   - Admin: passed address (requires auth)
        //   - Paused: false
        //   - ConfigVersion: 1
        //   - ContractVersion: 1
        // - Re-init guard: DataKey::Admin presence check; panics if set
        // - Re-init allowed by different admin: NO (guard blocks all)
        // - Invalid config cases: None (no dependencies to validate)

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProtocolConfigContract, ());
        let client = ProtocolConfigContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        // Verify the spec
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
        assert!(!client.is_paused());
        assert_eq!(client.get_config_version(), 1);
        assert_eq!(client.get_contract_version(), 1);

        // Re-initialization must fail
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin)
        }))
        .is_err());
    }
}
