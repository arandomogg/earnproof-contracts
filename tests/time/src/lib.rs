#![no_std]

//! Deterministic ledger-time boundary tests. All timestamps are explicit.
//!
//! Tests cover:
//! - Proof expiry boundaries (before, at, after)
//! - Schema deprecation time boundaries
//! - Timestamp overflow and zero values
//! - Revocation dominates expiry
//! - Record timestamp correctness (created_at, revoked_at)
//! - Cross-cutting interactions (multi-proof expiry, revoke-then-expire)

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use earnproof_shared::{ProofError, ProofStatus};
    use issuer_registry::{IssuerRegistryContract, IssuerRegistryContractClient};
    use proof_registry::{ProofRegistryContract, ProofRegistryContractClient};
    use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};
    use soroban_sdk::testutils::{Address as _, Ledger as _};
    use soroban_sdk::{Address, BytesN, Env};

    const NOW: u64 = 1_000;

    // ── Reusable LedgerClock ────────────────────────────────────────────────

    /// Deterministic clock for controlling `env.ledger().timestamp()`.
    ///
    /// All time progression is explicit: call [`LedgerClock::advance`] or
    /// [`LedgerClock::set_to`] rather than reading wall-clock time. This makes
    /// every test fully reproducible.
    struct LedgerClock {
        env: Env,
    }

    #[allow(dead_code)]
    impl LedgerClock {
        /// Create a new clock anchored at `start_timestamp`.
        fn new(start_timestamp: u64) -> Self {
            let env = Env::default();
            env.mock_all_auths();
            env.ledger().set_timestamp(start_timestamp);
            Self { env }
        }

        /// Advance the clock by `seconds` from its current position.
        fn advance(&self, seconds: u64) {
            let now = self.env.ledger().timestamp();
            self.env.ledger().set_timestamp(now + seconds);
        }

        /// Set the clock to an absolute `timestamp`.
        fn set_to(&self, timestamp: u64) {
            self.env.ledger().set_timestamp(timestamp);
        }

        /// Return the current ledger timestamp.
        fn now(&self) -> u64 {
            self.env.ledger().timestamp()
        }
    }

    // ── Fixture ─────────────────────────────────────────────────────────────

    struct Fixture {
        clock: LedgerClock,
        proofs: ProofRegistryContractClient<'static>,
        config: ProtocolConfigContractClient<'static>,
        issuer: Address,
    }

    fn bytes(env: &Env, value: u8) -> BytesN<32> {
        BytesN::from_array(env, &[value; 32])
    }

    fn fixture() -> Fixture {
        let clock = LedgerClock::new(NOW);
        let admin = Address::generate(&clock.env);
        let issuer = Address::generate(&clock.env);
        let config_id = clock.env.register(ProtocolConfigContract, ());
        let config = ProtocolConfigContractClient::new(&clock.env, &config_id);
        config.initialize(&admin);
        config.approve_schema_version(&1);
        let issuers_id = clock.env.register(IssuerRegistryContract, ());
        let issuers = IssuerRegistryContractClient::new(&clock.env, &issuers_id);
        issuers.initialize(&admin);
        issuers.register_issuer(&bytes(&clock.env, 1), &issuer, &bytes(&clock.env, 2));
        let proofs_id = clock.env.register(ProofRegistryContract, ());
        let proofs = ProofRegistryContractClient::new(&clock.env, &proofs_id);
        proofs.initialize(&admin, &issuers_id, &config_id);
        Fixture {
            clock,
            proofs,
            config,
            issuer,
        }
    }

    fn register(fixture: &Fixture, id: u8, expires_at: u64) {
        fixture.proofs.register_proof(
            &bytes(&fixture.clock.env, id),
            &bytes(&fixture.clock.env, id.wrapping_add(10)),
            &fixture.issuer,
            &1,
            &expires_at,
        );
    }

    // ── Existing tests (preserved) ──────────────────────────────────────────

    #[test]
    fn validity_is_inclusive_at_expiration_and_false_after() {
        let fixture = fixture();
        register(&fixture, 1, NOW + 10);
        fixture.clock.set_to(NOW + 10);
        assert!(fixture.proofs.is_valid_proof(&bytes(&fixture.clock.env, 1)));
        fixture.clock.set_to(NOW + 11);
        assert!(!fixture.proofs.is_valid_proof(&bytes(&fixture.clock.env, 1)));
    }

    #[test]
    fn registration_requires_strictly_future_expiration() {
        let fixture = fixture();
        for (id, expires_at) in [(1, NOW - 1), (2, NOW), (3, 0)] {
            assert_eq!(
                fixture.proofs.try_register_proof(
                    &bytes(&fixture.clock.env, id),
                    &bytes(&fixture.clock.env, id + 10),
                    &fixture.issuer,
                    &1,
                    &expires_at,
                ),
                Err(Ok(ProofError::ProofExpired))
            );
        }
    }

    #[test]
    fn revocation_dominates_expiration() {
        let fixture = fixture();
        register(&fixture, 4, NOW + 10);
        fixture.clock.set_to(NOW + 10);
        fixture.proofs.revoke_proof(&bytes(&fixture.clock.env, 4));
        fixture.clock.set_to(NOW + 11);
        assert!(!fixture.proofs.is_valid_proof(&bytes(&fixture.clock.env, 4)));
        assert!(fixture.proofs.is_revoked(&bytes(&fixture.clock.env, 4)));
    }

    #[test]
    fn zero_schema_and_pause_are_deterministic_guards() {
        let fixture = fixture();
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 5),
                &bytes(&fixture.clock.env, 6),
                &fixture.issuer,
                &0,
                &(NOW + 1)
            ),
            Err(Ok(ProofError::InvalidSchemaVersion))
        );
        fixture.config.pause();
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 7),
                &bytes(&fixture.clock.env, 8),
                &fixture.issuer,
                &1,
                &(NOW + 1)
            ),
            Err(Ok(ProofError::ContractPaused))
        );
    }

    #[test]
    fn maximum_timestamp_is_representable_without_interval_overflow() {
        let fixture = fixture();
        register(&fixture, 9, u64::MAX);
        assert!(fixture.proofs.is_valid_proof(&bytes(&fixture.clock.env, 9)));
    }

    // ── Proof expiry boundary tests ─────────────────────────────────────────

    #[test]
    fn proof_valid_before_expiry() {
        let fixture = fixture();
        register(&fixture, 10, NOW + 10);
        fixture.clock.set_to(NOW + 9);
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 10)));
    }

    #[test]
    fn proof_valid_at_exact_expiry() {
        let fixture = fixture();
        register(&fixture, 11, NOW + 10);
        fixture.clock.set_to(NOW + 10);
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 11)));
    }

    #[test]
    fn proof_invalid_after_expiry() {
        let fixture = fixture();
        register(&fixture, 12, NOW + 10);
        fixture.clock.set_to(NOW + 11);
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 12)));
    }

    // ── Schema deprecation time boundary tests ──────────────────────────────

    #[test]
    fn deprecated_schema_rejects_new_registrations() {
        let fixture = fixture();
        fixture.config.deprecate_schema_version(&1);
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 20),
                &bytes(&fixture.clock.env, 30),
                &fixture.issuer,
                &1,
                &(NOW + 1),
            ),
            Err(Ok(ProofError::UnsupportedSchema))
        );
    }

    #[test]
    fn schema_deprecation_takes_effect_immediately() {
        let fixture = fixture();
        // Approve and deprecate at the same timestamp — no time passes.
        fixture.config.approve_schema_version(&2);
        fixture.config.deprecate_schema_version(&2);
        assert!(!fixture.config.is_schema_version_approved(&2));
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 21),
                &bytes(&fixture.clock.env, 31),
                &fixture.issuer,
                &2,
                &(NOW + 1),
            ),
            Err(Ok(ProofError::UnsupportedSchema))
        );
    }

    #[test]
    fn proof_registered_before_deprecation_remains_valid() {
        let fixture = fixture();
        register(&fixture, 22, NOW + 100);
        // Schema is deprecated after the proof was registered.
        fixture.config.deprecate_schema_version(&1);
        // The existing proof is still valid — deprecation only gates new registrations.
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 22)));
        // But a new registration against the same (now deprecated) schema fails.
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 23),
                &bytes(&fixture.clock.env, 33),
                &fixture.issuer,
                &1,
                &(NOW + 100),
            ),
            Err(Ok(ProofError::UnsupportedSchema))
        );
    }

    // ── Timestamp overflow and zero value tests ─────────────────────────────

    #[test]
    fn zero_expires_at_rejected() {
        let fixture = fixture();
        assert_eq!(
            fixture.proofs.try_register_proof(
                &bytes(&fixture.clock.env, 40),
                &bytes(&fixture.clock.env, 50),
                &fixture.issuer,
                &1,
                &0,
            ),
            Err(Ok(ProofError::ProofExpired))
        );
    }

    #[test]
    fn one_is_valid_expires_at_when_now_is_zero() {
        let clock = LedgerClock::new(0);
        let admin = Address::generate(&clock.env);
        let issuer = Address::generate(&clock.env);
        let config_id = clock.env.register(ProtocolConfigContract, ());
        let config = ProtocolConfigContractClient::new(&clock.env, &config_id);
        config.initialize(&admin);
        config.approve_schema_version(&1);
        let issuers_id = clock.env.register(IssuerRegistryContract, ());
        let issuers = IssuerRegistryContractClient::new(&clock.env, &issuers_id);
        issuers.initialize(&admin);
        issuers.register_issuer(&bytes(&clock.env, 1), &issuer, &bytes(&clock.env, 2));
        let proofs_id = clock.env.register(ProofRegistryContract, ());
        let proofs = ProofRegistryContractClient::new(&clock.env, &proofs_id);
        proofs.initialize(&admin, &issuers_id, &config_id);

        // expires_at = 1, now = 0 → 1 > 0, should succeed.
        proofs.register_proof(
            &bytes(&clock.env, 41),
            &bytes(&clock.env, 51),
            &issuer,
            &1,
            &1,
        );
        assert!(proofs.is_valid_proof(&bytes(&clock.env, 41)));
    }

    // ── Revocation dominates expiry (comprehensive) ─────────────────────────

    #[test]
    fn revocation_before_expiry_makes_invalid() {
        let fixture = fixture();
        register(&fixture, 50, NOW + 100);
        // Revoke well before natural expiry.
        fixture.clock.set_to(NOW + 5);
        fixture.proofs.revoke_proof(&bytes(&fixture.clock.env, 50));
        // Even though we're before expiry, revocation makes it invalid.
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 50)));
        assert!(fixture.proofs.is_revoked(&bytes(&fixture.clock.env, 50)));
    }

    #[test]
    fn revoked_at_timestamp_is_correct() {
        let fixture = fixture();
        register(&fixture, 51, NOW + 100);
        let revoke_time = NOW + 42;
        fixture.clock.set_to(revoke_time);
        fixture.proofs.revoke_proof(&bytes(&fixture.clock.env, 51));
        let record = fixture.proofs.get_proof(&bytes(&fixture.clock.env, 51));
        assert_eq!(record.revoked_at, revoke_time);
    }

    // ── Record timestamp correctness ────────────────────────────────────────

    #[test]
    fn created_at_matches_registration_timestamp() {
        let fixture = fixture();
        register(&fixture, 60, NOW + 100);
        let record = fixture.proofs.get_proof(&bytes(&fixture.clock.env, 60));
        assert_eq!(record.created_at, NOW);
        assert_eq!(record.expires_at, NOW + 100);
        assert_eq!(record.status, ProofStatus::Active);
    }

    #[test]
    fn revoked_at_zero_until_revoked() {
        let fixture = fixture();
        register(&fixture, 61, NOW + 100);
        let record = fixture.proofs.get_proof(&bytes(&fixture.clock.env, 61));
        assert_eq!(record.revoked_at, 0);
    }

    // ── Interaction tests ───────────────────────────────────────────────────

    #[test]
    fn multiple_proofs_different_expiry_times() {
        let fixture = fixture();
        register(&fixture, 70, NOW + 10);
        register(&fixture, 71, NOW + 20);
        register(&fixture, 72, NOW + 30);

        // All valid at NOW.
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));

        // At NOW+10: 70 valid (inclusive), 71 and 72 still valid.
        fixture.clock.set_to(NOW + 10);
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));

        // At NOW+11: 70 expired, 71 and 72 still valid.
        fixture.clock.set_to(NOW + 11);
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));

        // At NOW+20: 70 expired, 71 valid (inclusive), 72 still valid.
        fixture.clock.set_to(NOW + 20);
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));

        // At NOW+21: 70 and 71 expired, 72 still valid.
        fixture.clock.set_to(NOW + 21);
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));

        // At NOW+31: all expired.
        fixture.clock.set_to(NOW + 31);
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 70)));
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 71)));
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 72)));
    }

    #[test]
    fn revoked_proof_ignores_expiry_advance() {
        let fixture = fixture();
        register(&fixture, 80, NOW + 10);
        // Revoke before expiry.
        fixture.clock.set_to(NOW + 5);
        fixture.proofs.revoke_proof(&bytes(&fixture.clock.env, 80));
        // Advance well past expiry.
        fixture.clock.set_to(NOW + 100);
        // Still revoked, not valid — revocation is terminal.
        assert!(fixture.proofs.is_revoked(&bytes(&fixture.clock.env, 80)));
        assert!(!fixture
            .proofs
            .is_valid_proof(&bytes(&fixture.clock.env, 80)));
        // revoked_at was set at the time of revocation, not at expiry.
        let record = fixture.proofs.get_proof(&bytes(&fixture.clock.env, 80));
        assert_eq!(record.revoked_at, NOW + 5);
    }
}
