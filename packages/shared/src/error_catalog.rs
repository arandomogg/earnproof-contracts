//! The reviewed catalog of every public contract error.
//!
//! The error enums in this crate define the codes. This module says what each
//! code means to a caller: what caused it, whether retrying can ever help,
//! what a client should do about it, and what a client may safely say to an end
//! user.
//!
//! The catalog is machine-readable so that three things can be checked rather
//! than asserted in prose, all of them in `tests/error-catalog/`:
//!
//! * every enum variant has a catalog entry with a matching code, so a new
//!   error cannot be added without being documented;
//! * the codes in [`docs/errors.md`](../../../docs/errors.md) and in the golden
//!   fixture match the catalog, so renumbering or reuse is caught;
//! * the codes the contracts actually return on each failure path match the
//!   catalog, so the documentation describes the deployed behaviour rather than
//!   the intended one.
//!
//! ## Codes are stable
//!
//! A published code is never reused for a different meaning and never
//! renumbered. Clients pin behaviour to the number, not to the variant name.
//! Removing an error is a breaking change; adding one is not, provided clients
//! follow the unknown-code rule below.
//!
//! ## Unknown codes
//!
//! A client will eventually meet a code that did not exist when it was written.
//! [`domain_for`] classifies any `u32` by range so that an unknown code is
//! still attributable to a contract, and [`retry_for`] answers the only
//! question that matters at that moment: an unknown code is never
//! automatically retried. See
//! [`docs/backend-integration.md`](../../../docs/backend-integration.md) for a
//! worked example.

/// Whether a code is returned by the current release.
///
/// A code can be declared in an error enum without any contract path returning
/// it. Publishing that distinction matters: for example, [`ProofError::MalformedInput`]
/// is declared and reserved but returned by no path in the current release.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Status {
    /// At least one contract path returns this code in the current release.
    Returned,
    /// Declared and reserved, but returned by no path in the current release.
    /// The code stays allocated so it can never mean something else later.
    Reserved,
}

impl Status {
    /// Stable lower-case name used in documentation and golden fixtures.
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Returned => "returned",
            Status::Reserved => "reserved",
        }
    }
}

/// Whether retrying the same call can ever succeed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Retry {
    /// The call is deterministically rejected. Retrying it unchanged will fail
    /// identically, forever. This is also the classification for any code a
    /// client does not recognise.
    Never,
    /// The call succeeds once an operator or admin changes protocol state:
    /// unpausing, initializing, approving a schema version, or reactivating an
    /// issuer. A client may retry on a schedule, but no amount of retrying
    /// alone resolves it.
    AfterOperatorAction,
    /// The call succeeds if the caller changes the request: a different
    /// identifier, a later expiration, an approved schema version. Retrying
    /// the identical request will not help.
    AfterCallerChange,
}

impl Retry {
    /// Stable lower-case name used in documentation and golden fixtures.
    pub const fn as_str(self) -> &'static str {
        match self {
            Retry::Never => "never",
            Retry::AfterOperatorAction => "after-operator-action",
            Retry::AfterCallerChange => "after-caller-change",
        }
    }
}

/// Which contract or shared range a code belongs to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Domain {
    /// 1-99, shared by every contract.
    Common,
    /// 100-199, reserved for protocol-config specific errors. Currently empty:
    /// protocol-config returns common errors only.
    ProtocolConfig,
    /// 200-299, issuer-registry specific.
    IssuerRegistry,
    /// 300-399, proof-registry specific.
    ProofRegistry,
    /// Outside every allocated range. A code here did not come from these
    /// contracts, or came from a version that allocated a new range.
    Unallocated,
}

impl Domain {
    /// Stable lower-case name used in documentation and golden fixtures.
    pub const fn as_str(self) -> &'static str {
        match self {
            Domain::Common => "common",
            Domain::ProtocolConfig => "protocol-config",
            Domain::IssuerRegistry => "issuer-registry",
            Domain::ProofRegistry => "proof-registry",
            Domain::Unallocated => "unallocated",
        }
    }

    /// Inclusive code range owned by this domain, if it owns one.
    pub const fn range(self) -> Option<(u32, u32)> {
        match self {
            Domain::Common => Some((1, 99)),
            Domain::ProtocolConfig => Some((100, 199)),
            Domain::IssuerRegistry => Some((200, 299)),
            Domain::ProofRegistry => Some((300, 399)),
            Domain::Unallocated => None,
        }
    }
}

/// One published error.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ErrorSpec {
    /// Stable numeric code. Never reused, never renumbered.
    pub code: u32,
    /// Variant name, for logs and for humans. Clients must not switch on it.
    pub name: &'static str,
    /// Rust enum the variant belongs to.
    pub enum_name: &'static str,
    /// Range the code belongs to.
    pub domain: Domain,
    /// Whether any contract path returns this code in the current release.
    pub status: Status,
    /// What the contract observed that led to this error.
    pub cause: &'static str,
    /// Whether retrying can help, and under what condition.
    pub retry: Retry,
    /// What the operator or backend should do about it.
    pub remediation: &'static str,
    /// Suggested HTTP status for a backend surfacing this to an API client.
    pub http_status: u16,
    /// Message a client may show an end user. Every message here is a fixed
    /// string: no identifier, address, hash, or record content is interpolated
    /// into it, because the error itself carries no such data to interpolate.
    pub client_message: &'static str,
}

/// Every published error, ordered by code.
pub const ERROR_CATALOG: [ErrorSpec; 25] = [
    ErrorSpec {
        code: 1,
        name: "AlreadyInitialized",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Returned,
        cause: "initialize was called on a contract that already has an admin.",
        retry: Retry::Never,
        remediation: "Treat the deployment as already provisioned. Verify the recorded admin before assuming the deployment is the one you expected.",
        http_status: 409,
        client_message: "Contract is already initialized",
    },
    ErrorSpec {
        code: 2,
        name: "NotInitialized",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Returned,
        cause: "A call read instance state on a contract that was never initialized.",
        retry: Retry::AfterOperatorAction,
        remediation: "Initialize the contract, or point the client at the correct deployed address. Do not retry against the same uninitialized contract.",
        http_status: 500,
        client_message: "Service temporarily unavailable",
    },
    ErrorSpec {
        code: 20,
        name: "Unauthorized",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Reserved,
        cause: "Reserved for an explicit authorization rejection. The contracts currently enforce authorization through require_auth, which aborts the invocation with a host authorization error rather than returning this code.",
        retry: Retry::Never,
        remediation: "Sign with the address the operation requires. Clients must treat a host authorization abort and this code as the same outcome, and neither reveals which address would have been accepted.",
        http_status: 403,
        client_message: "Insufficient permissions",
    },
    ErrorSpec {
        code: 40,
        name: "AlreadyExists",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Reserved,
        cause: "Reserved for a generic duplicate-write rejection. The registries return their own specific codes instead: 200, 202, and 300.",
        retry: Retry::Never,
        remediation: "Read the existing record instead of rewriting it. Handle the specific codes 200, 202, and 300, and treat this one as a forward-compatible synonym.",
        http_status: 409,
        client_message: "Resource already exists",
    },
    ErrorSpec {
        code: 41,
        name: "NotFound",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Reserved,
        cause: "Reserved for a generic missing-record rejection. The registries return their own specific codes instead: 201, 203, and 301.",
        retry: Retry::AfterCallerChange,
        remediation: "Confirm the identifier hash was derived with the documented hashing rules. Handle the specific codes 201, 203, and 301, and treat this one as a forward-compatible synonym.",
        http_status: 404,
        client_message: "Resource not found",
    },
    ErrorSpec {
        code: 42,
        name: "InvalidState",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Reserved,
        cause: "Reserved for a generic lifecycle rejection. The issuer registry returns 204 and 206 instead, and the proof registry returns 302.",
        retry: Retry::Never,
        remediation: "Read the current status and choose an operation the lifecycle allows. Handle the specific codes 204, 206, and 302, and treat this one as a forward-compatible synonym.",
        http_status: 400,
        client_message: "Operation not permitted in current state",
    },
    ErrorSpec {
        code: 60,
        name: "InvalidInput",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Returned,
        cause: "An argument failed validation, such as a zero schema version.",
        retry: Retry::AfterCallerChange,
        remediation: "Correct the argument. Retrying the identical request will fail identically.",
        http_status: 400,
        client_message: "Invalid input provided",
    },
    ErrorSpec {
        code: 80,
        name: "ProtocolPaused",
        enum_name: "ContractError",
        domain: Domain::Common,
        status: Status::Reserved,
        cause: "Reserved for the pause rejection. A paused protocol is currently reported by the proof registry as 304, not as this code.",
        retry: Retry::AfterOperatorAction,
        remediation: "Poll is_paused rather than waiting for this code: a paused protocol surfaces as 304 in the current release. Treat both as the same operator-action outcome.",
        http_status: 503,
        client_message: "Service temporarily paused",
    },
    ErrorSpec {
        code: 200,
        name: "IssuerAlreadyRegistered",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "register_issuer was called with an issuer_id_hash that already has a record.",
        retry: Retry::Never,
        remediation: "Use update_issuer to change metadata, or rotate_issuer_address to change the address. Registration is one-time per identifier.",
        http_status: 409,
        client_message: "Issuer already registered",
    },
    ErrorSpec {
        code: 201,
        name: "IssuerNotFound",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "A call referenced an issuer_id_hash with no record, or the registry has no admin yet.",
        retry: Retry::AfterCallerChange,
        remediation: "Register the issuer first, or confirm the identifier hash. If the registry is uninitialized, every call returns this code until an admin is set.",
        http_status: 404,
        client_message: "Issuer not found",
    },
    ErrorSpec {
        code: 202,
        name: "IssuerAddressAlreadyRegistered",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "A registration or rotation targeted a Stellar address already bound to an issuer.",
        retry: Retry::Never,
        remediation: "Choose an unused address. An address maps to at most one issuer so that address-based lookups stay unambiguous.",
        http_status: 409,
        client_message: "Issuer address already registered",
    },
    ErrorSpec {
        code: 203,
        name: "IssuerAddressNotFound",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "An address lookup found no entry in the reverse index.",
        retry: Retry::AfterCallerChange,
        remediation: "The address is not a registered issuer. Note that a rotated-away address returns this code, because the old index entry is removed.",
        http_status: 404,
        client_message: "Issuer address not found",
    },
    ErrorSpec {
        code: 204,
        name: "IssuerRevoked",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "The operation targeted an issuer whose status is Revoked.",
        retry: Retry::Never,
        remediation: "Revocation is terminal. Register a new issuer identifier if the party is to be readmitted.",
        http_status: 403,
        client_message: "Issuer has been revoked",
    },
    ErrorSpec {
        code: 205,
        name: "IssuerInactive",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Reserved,
        cause: "Reserved for the suspended-issuer rejection. A suspended issuer is currently reported by the proof registry as 304, not as this code.",
        retry: Retry::AfterOperatorAction,
        remediation: "Call is_active_address before registering rather than waiting for this code: a suspended issuer surfaces as 304 in the current release. An admin must reactivate the issuer; suspension is reversible, revocation is not.",
        http_status: 403,
        client_message: "Issuer is not active",
    },
    ErrorSpec {
        code: 206,
        name: "InvalidTransition",
        enum_name: "IssuerError",
        domain: Domain::IssuerRegistry,
        status: Status::Returned,
        cause: "A status change was requested that the lifecycle does not allow, such as reactivating a revoked issuer.",
        retry: Retry::Never,
        remediation: "Read the current status and choose a permitted transition.",
        http_status: 400,
        client_message: "Invalid status transition",
    },
    ErrorSpec {
        code: 300,
        name: "ProofAlreadyRegistered",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "register_proof was called with a proof_id_hash that already has a record.",
        retry: Retry::Never,
        remediation: "Proof records are immutable once written, including after archival and restoration. Register a new identifier rather than replacing a commitment.",
        http_status: 409,
        client_message: "Proof already registered",
    },
    ErrorSpec {
        code: 301,
        name: "ProofNotFound",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "A call referenced a proof_id_hash with no record, or the proof registry has no instance state to read its dependencies from.",
        retry: Retry::AfterCallerChange,
        remediation: "Confirm the identifier hash. If register_proof returns this code, the registry itself is uninitialized and no write took place.",
        http_status: 404,
        client_message: "Proof not found",
    },
    ErrorSpec {
        code: 302,
        name: "ProofAlreadyRevoked",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "A revocation targeted a proof already in the Revoked state.",
        retry: Retry::Never,
        remediation: "Treat the revocation as complete. Revocation is terminal and idempotent in effect, though not in return value.",
        http_status: 400,
        client_message: "Proof already revoked",
    },
    ErrorSpec {
        code: 303,
        name: "ProofExpired",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "register_proof was given an expires_at at or before the current ledger timestamp.",
        retry: Retry::AfterCallerChange,
        remediation: "Send an expiration in the future relative to ledger time, not to wall-clock time on the calling host.",
        http_status: 400,
        client_message: "Invalid proof expiration",
    },
    ErrorSpec {
        code: 304,
        name: "InvalidSchemaVersion",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "register_proof was given schema version zero, or a precondition that the registry currently reports through this same code failed: the protocol is paused, or the issuer address is not active.",
        retry: Retry::AfterOperatorAction,
        remediation: "Check three things in order: that the schema version is non-zero, that is_paused is false, and that is_active_address is true for the issuer. This code is overloaded in the current release; see the ambiguity note in docs/errors.md.",
        http_status: 400,
        client_message: "Invalid schema version",
    },
    ErrorSpec {
        code: 305,
        name: "SchemaVersionNotApproved",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "The schema version is non-zero but is not approved in protocol-config, either because it was never approved or because it was deprecated.",
        retry: Retry::AfterOperatorAction,
        remediation: "A protocol operator must approve the version. A registry pointed at an uninitialized protocol config also returns this code, because no version can be approved there.",
        http_status: 400,
        client_message: "Schema version not approved",
    },
    ErrorSpec {
        code: 307,
        name: "ContractPaused",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "The proof registry detected that the protocol is paused and rejected proof registration.",
        retry: Retry::AfterOperatorAction,
        remediation: "Call is_paused on the protocol config contract to check if the pause is active. An operator must unpause the protocol to allow proof registration to resume.",
        http_status: 503,
        client_message: "Contract is paused",
    },
    ErrorSpec {
        code: 308,
        name: "IssuerInactive",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "The issuer address is not active or was suspended.",
        retry: Retry::AfterOperatorAction,
        remediation: "Call is_active_address on the issuer registry to confirm the issuer is active. An operator must reactivate the issuer if it was suspended.",
        http_status: 403,
        client_message: "Issuer is not active",
    },
    ErrorSpec {
        code: 309,
        name: "UnsupportedSchema",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Returned,
        cause: "The proof schema identifier is not supported or not registered in the protocol config.",
        retry: Retry::AfterOperatorAction,
        remediation: "Call is_schema_version_approved on the protocol config contract to verify the schema version is approved. An operator must approve the schema version before it can be used for proof registration.",
        http_status: 400,
        client_message: "Schema not supported",
    },
    ErrorSpec {
        code: 310,
        name: "MalformedInput",
        enum_name: "ProofError",
        domain: Domain::ProofRegistry,
        status: Status::Reserved,
        cause: "Reserved for when proof input data fails format or size validation. No contract path currently returns this code; it is allocated so the code is never reused for a different meaning.",
        retry: Retry::AfterCallerChange,
        remediation: "Validate the proof input data against the schema before resubmitting. Ensure all required fields are present and data sizes conform to the schema limits.",
        http_status: 400,
        client_message: "Malformed proof input",
    },
];

/// Looks up a published error by code.
pub fn spec(code: u32) -> Option<ErrorSpec> {
    ERROR_CATALOG.into_iter().find(|entry| entry.code == code)
}

/// Classifies any code by range, including codes this build has never seen.
///
/// A backend uses this to attribute an unknown error to a contract without
/// guessing what it means.
pub fn domain_for(code: u32) -> Domain {
    match code {
        1..=99 => Domain::Common,
        100..=199 => Domain::ProtocolConfig,
        200..=299 => Domain::IssuerRegistry,
        300..=399 => Domain::ProofRegistry,
        _ => Domain::Unallocated,
    }
}

/// Retry classification for any code, known or not.
///
/// An unknown code is [`Retry::Never`]. A client that has never seen a code
/// cannot know whether the call had a side effect, so retrying it
/// automatically is never safe; the call belongs in front of a human or in a
/// queue that a newer client version will drain.
pub fn retry_for(code: u32) -> Retry {
    match spec(code) {
        Some(entry) => entry.retry,
        None => Retry::Never,
    }
}
