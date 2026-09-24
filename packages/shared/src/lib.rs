#![no_std]

use soroban_sdk::{contracterror, contracttype, Address, BytesN};

pub mod storage_namespaces;

pub use storage_namespaces::{StorageClass, StorageNamespace, STORAGE_NAMESPACES};
pub mod error_catalog;

pub use error_catalog::{Domain, ErrorSpec, Retry, Status, ERROR_CATALOG};

pub const TTL_THRESHOLD_LEDGERS: u32 = 50_000;

/// Target ledgers for extended TTL after triggering a preemptive extension.
pub const TTL_EXTEND_TO_LEDGERS: u32 = 500_000;

// A Stellar strkey address (G...) is always exactly 56 ASCII characters.
// soroban_sdk::String has no .chars() (unlike std::string::String, and
// unlike Symbol, this isn't even gated off-WASM only - it simply doesn't
// exist on any target in this SDK version) and doesn't implement
// PartialEq<&str>, only String == String - copy_into_slice() into a fixed
// buffer and comparing raw ASCII bytes is the actual supported way to
// inspect a soroban_sdk::String's contents on every target.
const STRKEY_ADDRESS_LEN: usize = 56;

fn address_bytes(address: &Address) -> [u8; STRKEY_ADDRESS_LEN] {
    let value = address.to_string();
    let mut buf = [0u8; STRKEY_ADDRESS_LEN];
    if value.len() as usize == STRKEY_ADDRESS_LEN {
        value.copy_into_slice(&mut buf);
    }
    buf
}

// The strkey encoding of an all-zero (32-byte) ed25519 public key: version
// byte 'G' + 32 zero payload bytes + a real CRC16/XMODEM checksum over
// those 33 bytes, base32-encoded. The checksum is NOT itself all zero bits
// (a correct checksum over an all-zero payload is not the all-zero
// checksum), so this string does not end in all 'A's — comparing the
// full string against this one known-correct value is the only way to
// recognize it; a pattern check like "G followed by all A's" would (and
// previously did) silently never match a real, correctly-checksummed
// all-zero-payload address at all.
const ZERO_PAYLOAD_STRKEY: &[u8; STRKEY_ADDRESS_LEN] =
    b"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

pub fn is_zero_or_sentinel_address(address: &Address) -> bool {
    let bytes = address_bytes(address);
    &bytes == ZERO_PAYLOAD_STRKEY
}

// ---------------------------------------------------------------------------
// Dependency interface versioning
//
// Cross-contract dependencies expose a machine-readable interface version so
// that a consumer (e.g. proof-registry) can refuse to bind to a dependency
// whose interface it does not understand.
//
// The version follows a semver-style major/minor/patch tuple:
//   - A `major` bump is a breaking change: the consumer must match it exactly.
//   - `minor`/`patch` are backward compatible within the same `major`: a
//     dependency may advance them freely and remain acceptable, but it must be
//     at least the minimum the consumer requires.
//
// Compatibility rule (see `is_interface_compatible`):
//   actual.major == required.major
//     && (actual.minor, actual.patch) >= (required.minor, required.patch)
// ---------------------------------------------------------------------------

/// A machine-readable interface version exposed by a cross-contract dependency.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InterfaceVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl InterfaceVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        InterfaceVersion {
            major,
            minor,
            patch,
        }
    }
}

/// The interface version implemented by `issuer-registry`.
pub const ISSUER_REGISTRY_INTERFACE_VERSION: InterfaceVersion = InterfaceVersion::new(1, 0, 0);

/// The interface version implemented by `protocol-config`.
pub const PROTOCOL_CONFIG_INTERFACE_VERSION: InterfaceVersion = InterfaceVersion::new(1, 0, 0);

/// Returns true when `actual` is compatible with the `required` minimum.
///
/// The `major` component must match exactly (a breaking-change boundary); the
/// `minor`/`patch` components of `actual` must be greater than or equal to the
/// required minimum, compared lexicographically. Newer compatible dependencies
/// (higher minor/patch, same major) are therefore accepted.
pub fn is_interface_compatible(required: &InterfaceVersion, actual: &InterfaceVersion) -> bool {
    actual.major == required.major
        && (actual.minor, actual.patch) >= (required.minor, required.patch)
}

pub fn is_valid_principal_address(address: &Address) -> bool {
    let value = address.to_string();
    if value.is_empty() || value.len() as usize != STRKEY_ADDRESS_LEN {
        return false;
    }
    let bytes = address_bytes(address);
    if is_zero_or_sentinel_address(address) {
        return false;
    }
    bytes
        .iter()
        .all(|&byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7'))
}

// ---------------------------------------------------------------------------
// Error Codes
//
// Error ranges are allocated to prevent collisions:
// - Common errors:       1-99
// - Protocol Config:     100-199
// - Issuer Registry:     200-299
// - Proof Registry:      300-399
//
// Each error code is stable and machine-readable. Backend integrations
// should map these codes to appropriate HTTP status codes and user messages.
// ---------------------------------------------------------------------------

/// Common errors shared across all contracts.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    // Initialization errors (1-19)
    AlreadyInitialized = 1,
    NotInitialized = 2,

    // Authorization errors (20-39)
    Unauthorized = 20,

    // State errors (40-59)
    AlreadyExists = 40,
    NotFound = 41,
    InvalidState = 42,

    // Input validation errors (60-79)
    InvalidInput = 60,
    InvalidAddress = 61,
    /// A cross-contract dependency reported an interface version outside the
    /// range the consumer accepts.
    IncompatibleInterfaceVersion = 62,

    // Protocol state errors (80-99)
    ProtocolPaused = 80,
}

/// Issuer-specific errors (200-299).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum IssuerError {
    IssuerAlreadyRegistered = 200,
    IssuerNotFound = 201,
    IssuerAddressAlreadyRegistered = 202,
    IssuerAddressNotFound = 203,
    IssuerRevoked = 204,
    IssuerInactive = 205,
    InvalidTransition = 206,
    InvalidAddress = 207,
    /// Registering or reactivating this issuer would exceed the governed
    /// maximum active-issuer capacity.
    IssuerCapacityExceeded = 208,
    /// A requested capacity limit is below the current active-issuer usage and
    /// no explicit override was supplied.
    MaxBelowActiveUsage = 209,
    /// The suspended issuer's reactivation cooldown has not yet elapsed.
    ReactivationCooldownActive = 210,
}

/// Proof-specific errors (300-399).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProofError {
    ProofAlreadyRegistered = 300,
    ProofNotFound = 301,
    ProofAlreadyRevoked = 302,
    ProofExpired = 303,
    InvalidSchemaVersion = 304,
    SchemaVersionNotApproved = 305,
    InvalidAddress = 306,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuerStatus {
    Active,
    Suspended,
    Revoked,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofStatus {
    Active,
    Revoked,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub issuer_id_hash: BytesN<32>,
    pub issuer_address: Address,
    pub metadata_hash: BytesN<32>,
    pub status: IssuerStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub proof_id_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub issuer_address: Address,
    pub status: ProofStatus,
    pub schema_version: u32,
    pub expires_at: u64,
    pub created_at: u64,
    pub revoked_at: u64,
}

// ── Shared Test Utilities ──────────────────────────────────────────────────────
// These utilities provide common patterns for initialization adversarial testing
// across all contracts, ensuring consistent test coverage for re-initialization
// guards, invalid dependencies, and state/event immutability on failure.

#[cfg(test)]
mod interface_version_tests {
    use super::*;

    const BASE: InterfaceVersion = InterfaceVersion::new(1, 2, 3);

    #[test]
    fn exact_match_is_compatible() {
        assert!(is_interface_compatible(&BASE, &BASE));
    }

    #[test]
    fn newer_patch_and_minor_within_major_are_compatible() {
        assert!(is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(1, 2, 4)
        ));
        assert!(is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(1, 3, 0)
        ));
        assert!(is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(1, 9, 9)
        ));
    }

    #[test]
    fn older_minor_or_patch_is_incompatible() {
        assert!(!is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(1, 2, 2)
        ));
        assert!(!is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(1, 1, 9)
        ));
    }

    #[test]
    fn a_different_major_is_incompatible_in_both_directions() {
        assert!(!is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(2, 0, 0)
        ));
        assert!(!is_interface_compatible(
            &BASE,
            &InterfaceVersion::new(0, 9, 9)
        ));
    }
}

#[cfg(test)]
pub mod test_utils {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Represents the expected state after successful initialization.
    /// Used to verify that first initialization produces exactly the documented
    /// state with no partial writes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct InitializedState {
        /// The admin address that was set during initialization.
        pub admin: Address,
        /// True if the contract emitted an event during initialization.
        pub event_emitted: bool,
        /// Additional state keys that should be present after initialization.
        pub expected_keys: Vec<&'static str>,
    }

    /// Test result for re-initialization attempts.
    /// Captures whether the attempt failed and whether state remained unchanged.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ReinitAttemptResult {
        /// True if re-initialization attempt failed (panicked or errored).
        pub failed: bool,
        /// True if storage state is byte-for-byte identical before and after attempt.
        pub state_unchanged: bool,
        /// True if no new events were emitted during the failed attempt.
        pub no_new_events: bool,
    }

    /// Test result for invalid dependency/configuration initialization attempts.
    /// Captures whether the attempt failed and whether state remained atomic.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct InvalidDependencyResult {
        /// True if initialization attempt failed.
        pub failed: bool,
        /// True if storage state is unchanged after the failed attempt.
        pub atomic_failure: bool,
        /// True if no events were emitted during the failed attempt.
        pub no_events: bool,
    }

    /// Documents the initialization contract's behavior for test purposes.
    /// This structure is filled out for each contract being tested and serves
    /// as the specification against which adversarial tests validate behavior.
    #[derive(Clone, Debug)]
    pub struct ContractInitSpec {
        /// Name of the contract being tested.
        pub contract_name: &'static str,
        /// True if this contract has a re-initialization guard.
        pub has_reinit_guard: bool,
        /// True if this contract emits an event during initialization.
        pub emits_init_event: bool,
        /// True if this contract takes dependency addresses as initialization parameters.
        pub takes_dependencies: bool,
        /// List of dependency contract names this contract requires (e.g., ["issuer-registry", "protocol-config"]).
        pub dependency_names: Vec<&'static str>,
    }

    impl ContractInitSpec {
        /// Helper to create a spec for a standalone contract with a re-initialization guard.
        pub fn standalone_with_guard(name: &'static str, emits_event: bool) -> Self {
            ContractInitSpec {
                contract_name: name,
                has_reinit_guard: true,
                emits_init_event: emits_event,
                takes_dependencies: false,
                dependency_names: vec![],
            }
        }

        /// Helper to create a spec for a contract with dependencies and a re-initialization guard.
        pub fn with_dependencies_and_guard(
            name: &'static str,
            deps: Vec<&'static str>,
            emits_event: bool,
        ) -> Self {
            ContractInitSpec {
                contract_name: name,
                has_reinit_guard: true,
                emits_init_event: emits_event,
                takes_dependencies: true,
                dependency_names: deps,
            }
        }
    }
}
