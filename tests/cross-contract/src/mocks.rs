//! Substitute dependencies that fail at a chosen cross-contract boundary.
//!
//! `proof-registry` declares what it expects from its dependencies with
//! `#[contractclient]` traits:
//!
//! ```text
//! protocol-config: is_paused() -> bool
//!                  is_schema_version_approved(u32) -> bool
//! issuer-registry: is_active_address(Address) -> bool
//! ```
//!
//! Each contract below satisfies part of that shape and breaks the rest in one
//! specific way. Substituting one for the real dependency at `initialize` is
//! the only way to reach a failure *inside* a cross-contract read: the real
//! contracts answer every one of those calls successfully, whatever their
//! state, and signal their verdict through the returned `bool`.
//!
//! # Error codes
//!
//! `MockError` sits at 900-999, outside every range allocated in
//! `packages/shared/src/lib.rs` (1-99 common, 100-199 protocol config, 200-299
//! issuer registry, 300-399 proof registry). A dependency failure therefore
//! cannot be decoded as a `ProofError`, and
//! [`crate::harness::Rejection::Aborted`] is an unambiguous verdict rather than
//! an accident of code allocation.

// `#[contractimpl]` generates a client for every contract below. Only the
// stateful substitutes are read back through theirs, so the rest are
// deliberately unused.
#![allow(dead_code)]

use earnproof_shared::InterfaceVersion;
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, BytesN, Env};

/// The interface version a compatible substitute reports. Every substitute
/// below answers `interface_version` so that `proof-registry::initialize` passes
/// its dependency handshake and the scenario's chosen failure still surfaces
/// where the test targets it — during registration — rather than at init.
const COMPATIBLE_VERSION: InterfaceVersion = InterfaceVersion::new(1, 0, 0);

/// Rejection raised by a substitute dependency.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MockError {
    DependencyRejected = 901,
}

/// Storage keys used by the stateful substitutes.
#[contracttype]
enum MockKey {
    /// Address whose authorization [`ConfigRequiringAuth`] demands.
    Guardian,
    /// Set by [`RecordingConfig`] when its read runs.
    Touched,
    /// Pause flag owned by [`SelfPausingConfig`].
    Paused,
}

// ---------------------------------------------------------------------------
// Rejections at a chosen boundary
// ---------------------------------------------------------------------------

/// Rejects boundary 1. No read has succeeded when the registration fails.
#[contract]
pub struct RejectsPauseRead;

#[contractimpl]
impl RejectsPauseRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(_env: Env) -> Result<bool, MockError> {
        Err(MockError::DependencyRejected)
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> bool {
        true
    }
}

/// Rejects boundary 2, after boundary 1 has already succeeded.
#[contract]
pub struct RejectsSchemaRead;

#[contractimpl]
impl RejectsSchemaRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(_env: Env) -> bool {
        false
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> Result<bool, MockError> {
        Err(MockError::DependencyRejected)
    }
}

/// Rejects boundary 3, after both `protocol-config` reads have succeeded.
#[contract]
pub struct RejectsIssuerRead;

#[contractimpl]
impl RejectsIssuerRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_active_address(_env: Env, _issuer_address: Address) -> Result<bool, MockError> {
        Err(MockError::DependencyRejected)
    }
}

// ---------------------------------------------------------------------------
// Malformed return data
//
// The value is well-formed on the wire but is not the type the caller's
// interface declares, so the failure lands in the caller's conversion of the
// return value rather than in the callee. `7` rather than `0` or `1` so the
// test cannot pass by a lenient integer-to-bool coercion.
// ---------------------------------------------------------------------------

/// Returns `u32` from boundary 1 where `bool` is declared.
#[contract]
pub struct MalformedPauseRead;

#[contractimpl]
impl MalformedPauseRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(_env: Env) -> u32 {
        7
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> bool {
        true
    }
}

/// Returns `u32` from boundary 2.
#[contract]
pub struct MalformedSchemaRead;

#[contractimpl]
impl MalformedSchemaRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(_env: Env) -> bool {
        false
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> u32 {
        7
    }
}

/// Returns `u32` from boundary 3.
#[contract]
pub struct MalformedIssuerRead;

#[contractimpl]
impl MalformedIssuerRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_active_address(_env: Env, _issuer_address: Address) -> u32 {
        7
    }
}

// ---------------------------------------------------------------------------
// Version-incompatible dependencies
//
// `docs/compatibility.md` classifies both of these as **Breaking** ABI changes
// and warns that "a caller built against the old signature does not fail to
// compile — it fails at invocation, in production". These two contracts are
// that failure, made reproducible.
// ---------------------------------------------------------------------------

/// A `protocol-config` predating schema approval: it answers `is_paused` but
/// has no `is_schema_version_approved` entry point at all.
#[contract]
pub struct ConfigWithoutSchemaRead;

#[contractimpl]
impl ConfigWithoutSchemaRead {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(_env: Env) -> bool {
        false
    }
}

/// An `issuer-registry` whose `is_active_address` takes an issuer id hash
/// instead of an address — the same entry point name, a different parameter
/// type.
#[contract]
pub struct IssuersWithChangedSignature;

#[contractimpl]
impl IssuersWithChangedSignature {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_active_address(_env: Env, _issuer_id_hash: BytesN<32>) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Nested authorization
// ---------------------------------------------------------------------------

/// Demands authorization from a third address during boundary 1.
///
/// Nothing in the real deployment does this, but a dependency that is later
/// upgraded to gate a read behind an allow-list would, and the caller has no
/// way to anticipate it. The registration must fail closed rather than
/// proceeding on an unauthorised read.
#[contract]
pub struct ConfigRequiringAuth;

#[contractimpl]
impl ConfigRequiringAuth {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn set_guardian(env: Env, guardian: Address) {
        env.storage().instance().set(&MockKey::Guardian, &guardian);
    }

    pub fn is_paused(env: Env) -> bool {
        let guardian: Address = env
            .storage()
            .instance()
            .get(&MockKey::Guardian)
            .expect("the guardian is set before the deployment is used");
        guardian.require_auth();
        false
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Stateful substitutes
// ---------------------------------------------------------------------------

/// Writes to its own persistent storage during boundary 1, then answers
/// normally.
///
/// Used to show that the rollback of a failed registration reaches the
/// *callee*. Storage inside a dependency is invisible to `proof-registry`'s own
/// footprint, so without a contract like this one "no partial state" could only
/// be asserted for the caller.
#[contract]
pub struct RecordingConfig;

#[contractimpl]
impl RecordingConfig {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage().persistent().set(&MockKey::Touched, &true);
        false
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> bool {
        true
    }

    /// Whether the write performed during boundary 1 is still there.
    pub fn was_touched(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&MockKey::Touched)
            .unwrap_or(false)
    }
}

/// Reports its pause flag and sets it in the same read.
///
/// The only way to construct "a config update landing in the middle of a
/// registration" at all — see [`crate::races`] for why the ledger cannot
/// produce that situation on its own. The first registration observes `false`
/// and commits; every later one observes `true` and is rejected.
#[contract]
pub struct SelfPausingConfig;

#[contractimpl]
impl SelfPausingConfig {
    pub fn interface_version(_env: Env) -> InterfaceVersion {
        COMPATIBLE_VERSION
    }

    pub fn is_paused(env: Env) -> bool {
        let observed: bool = env
            .storage()
            .instance()
            .get(&MockKey::Paused)
            .unwrap_or(false);
        env.storage().instance().set(&MockKey::Paused, &true);
        observed
    }

    pub fn is_schema_version_approved(_env: Env, _version: u32) -> bool {
        true
    }

    /// The flag as it stands now.
    pub fn pause_flag(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&MockKey::Paused)
            .unwrap_or(false)
    }
}
