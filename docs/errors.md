# Contract Error Catalog

Every error these contracts can return, with a stable code, the condition that produces it, whether retrying can help, and what to do about it.

The catalog below is generated from [`packages/shared/src/error_catalog.rs`](../packages/shared/src/error_catalog.rs) and checked by [`tests/error-catalog/`](../tests/error-catalog/src/lib.rs). It is not maintained by hand: to change it, change the catalog and regenerate with

```
cargo test -p error-catalog-tests -- --ignored regenerate
```

Backend mapping guidance, including how to handle a code this document does not list, is in [Backend Integration](./backend-integration.md).

---

## How to read this

**Code** is the contract. Clients switch on the number, never on the variant name. A published code is never renumbered and never reused for a different meaning; removing one is a breaking change, adding one is not.

**Domain** is the allocated range the code falls in:

| Range | Domain | Enum |
|---|---|---|
| 1-99 | common | `ContractError` |
| 100-199 | protocol-config | none yet; reserved |
| 200-299 | issuer-registry | `IssuerError` |
| 300-399 | proof-registry | `ProofError` |

The protocol-config range is allocated but empty: that contract returns common errors only. The range stays reserved so a future protocol-config error cannot collide with anything.

**Status** distinguishes a code that some contract path actually returns from one that is declared and reserved but produced by nothing in this release. Six codes are currently reserved, and the distinction matters in practice: see the ambiguity note below before writing a client that waits for one of them.

**Retry** answers whether repeating the call can ever succeed:

| Retry | Meaning | What a client should do |
|---|---|---|
| `never` | Deterministic rejection | Surface it. Do not retry, on any schedule. |
| `after-operator-action` | Succeeds once an operator or admin changes protocol state | Queue or poll the relevant read (`is_paused`, `is_active_address`, `is_schema_version_approved`) rather than retrying the write blindly. |
| `after-caller-change` | Succeeds if the request itself changes | Fix the request. Retrying it unchanged fails identically. |

An unrecognised code is always `never`. A client that has not seen a code cannot know whether the call had a side effect, so replaying it is never safe.

---

## Overloaded codes in this release

The following codes are now properly separated (no longer overloaded):

**Previously (pre-fix):** Three conditions shared code `304 InvalidSchemaVersion`:
1. the schema version is zero;
2. the protocol is paused;
3. the issuer address is not active.

**Currently (post-fix):** Each precondition has its distinct code:

| Code | Condition | Retry | Recovery |
|------|-----------|-------|----------|
| 304  | schema version is zero | never | Use a non-zero schema version |
| 307  | protocol is paused | after-operator-action | Poll `is_paused` and wait for unpause |
| 308  | issuer is inactive | after-operator-action | Call `is_active_address` and wait for reactivation |
| 309  | schema not approved | after-operator-action | Call `is_schema_version_approved` and wait for approval |

This separation enables clients to distinguish between different failure modes and take appropriate recovery actions, rather than checking all three conditions blindly on receipt of 304.

---

## Disclosure

A Soroban contract error is a type and a number. It carries no message, no payload, and no record content, so a failing call cannot leak what it touched. Three properties follow, each asserted in the test crate:

- **Authorization failures are undifferentiated.** Every authorization rejection is the same outcome regardless of which address would have been accepted, and none reveals whether a record exists.
- **Client messages are fixed strings.** No entry contains an interpolation marker, so a client is never invited to splice an identifier into a message the contract did not provide.
- **No message names private data.** The on-chain record set is public by design, so a `not found` code is not a disclosure; the constraint is that the client-facing surface never grows toward commitment contents, metadata, or amounts, none of which are on-chain at all. See the [Storage Model](./storage-model.md) for the full on-chain data boundary.

---

<!-- BEGIN GENERATED: do not edit. -->

## Catalog

| Code | Name | Enum | Domain | Status | Retry | HTTP |
|---|---|---|---|---|---|---|
| 1 | `AlreadyInitialized` | `ContractError` | common | returned | never | 409 |
| 2 | `NotInitialized` | `ContractError` | common | returned | after-operator-action | 500 |
| 20 | `Unauthorized` | `ContractError` | common | reserved | never | 403 |
| 40 | `AlreadyExists` | `ContractError` | common | reserved | never | 409 |
| 41 | `NotFound` | `ContractError` | common | reserved | after-caller-change | 404 |
| 42 | `InvalidState` | `ContractError` | common | reserved | never | 400 |
| 60 | `InvalidInput` | `ContractError` | common | returned | after-caller-change | 400 |
| 80 | `ProtocolPaused` | `ContractError` | common | reserved | after-operator-action | 503 |
| 200 | `IssuerAlreadyRegistered` | `IssuerError` | issuer-registry | returned | never | 409 |
| 201 | `IssuerNotFound` | `IssuerError` | issuer-registry | returned | after-caller-change | 404 |
| 202 | `IssuerAddressAlreadyRegistered` | `IssuerError` | issuer-registry | returned | never | 409 |
| 203 | `IssuerAddressNotFound` | `IssuerError` | issuer-registry | returned | after-caller-change | 404 |
| 204 | `IssuerRevoked` | `IssuerError` | issuer-registry | returned | never | 403 |
| 205 | `IssuerInactive` | `IssuerError` | issuer-registry | reserved | after-operator-action | 403 |
| 206 | `InvalidTransition` | `IssuerError` | issuer-registry | returned | never | 400 |
| 300 | `ProofAlreadyRegistered` | `ProofError` | proof-registry | returned | never | 409 |
| 301 | `ProofNotFound` | `ProofError` | proof-registry | returned | after-caller-change | 404 |
| 302 | `ProofAlreadyRevoked` | `ProofError` | proof-registry | returned | never | 400 |
| 303 | `ProofExpired` | `ProofError` | proof-registry | returned | after-caller-change | 400 |
| 304 | `InvalidSchemaVersion` | `ProofError` | proof-registry | returned | never | 400 |
| 305 | `SchemaVersionNotApproved` | `ProofError` | proof-registry | returned | after-operator-action | 400 |
| 307 | `ContractPaused` | `ProofError` | proof-registry | returned | after-operator-action | 503 |
| 308 | `IssuerInactive` | `ProofError` | proof-registry | returned | after-operator-action | 403 |
| 309 | `UnsupportedSchema` | `ProofError` | proof-registry | returned | after-operator-action | 400 |
| 310 | `MalformedInput` | `ProofError` | proof-registry | reserved | after-caller-change | 400 |

## Details

### 1 - `AlreadyInitialized`

- Enum: `ContractError`
- Domain: common
- Status: returned
- Retry: never
- Cause: initialize was called on a contract that already has an admin.
- Remediation: Treat the deployment as already provisioned. Verify the recorded admin before assuming the deployment is the one you expected.
- Suggested HTTP status: 409
- Client message: "Contract is already initialized"

### 2 - `NotInitialized`

- Enum: `ContractError`
- Domain: common
- Status: returned
- Retry: after-operator-action
- Cause: A call read instance state on a contract that was never initialized.
- Remediation: Initialize the contract, or point the client at the correct deployed address. Do not retry against the same uninitialized contract.
- Suggested HTTP status: 500
- Client message: "Service temporarily unavailable"

### 20 - `Unauthorized`

- Enum: `ContractError`
- Domain: common
- Status: reserved
- Retry: never
- Cause: Reserved for an explicit authorization rejection. The contracts currently enforce authorization through require_auth, which aborts the invocation with a host authorization error rather than returning this code.
- Remediation: Sign with the address the operation requires. Clients must treat a host authorization abort and this code as the same outcome, and neither reveals which address would have been accepted.
- Suggested HTTP status: 403
- Client message: "Insufficient permissions"

### 40 - `AlreadyExists`

- Enum: `ContractError`
- Domain: common
- Status: reserved
- Retry: never
- Cause: Reserved for a generic duplicate-write rejection. The registries return their own specific codes instead: 200, 202, and 300.
- Remediation: Read the existing record instead of rewriting it. Handle the specific codes 200, 202, and 300, and treat this one as a forward-compatible synonym.
- Suggested HTTP status: 409
- Client message: "Resource already exists"

### 41 - `NotFound`

- Enum: `ContractError`
- Domain: common
- Status: reserved
- Retry: after-caller-change
- Cause: Reserved for a generic missing-record rejection. The registries return their own specific codes instead: 201, 203, and 301.
- Remediation: Confirm the identifier hash was derived with the documented hashing rules. Handle the specific codes 201, 203, and 301, and treat this one as a forward-compatible synonym.
- Suggested HTTP status: 404
- Client message: "Resource not found"

### 42 - `InvalidState`

- Enum: `ContractError`
- Domain: common
- Status: reserved
- Retry: never
- Cause: Reserved for a generic lifecycle rejection. The issuer registry returns 204 and 206 instead, and the proof registry returns 302.
- Remediation: Read the current status and choose an operation the lifecycle allows. Handle the specific codes 204, 206, and 302, and treat this one as a forward-compatible synonym.
- Suggested HTTP status: 400
- Client message: "Operation not permitted in current state"

### 60 - `InvalidInput`

- Enum: `ContractError`
- Domain: common
- Status: returned
- Retry: after-caller-change
- Cause: An argument failed validation, such as a zero schema version.
- Remediation: Correct the argument. Retrying the identical request will fail identically.
- Suggested HTTP status: 400
- Client message: "Invalid input provided"

### 80 - `ProtocolPaused`

- Enum: `ContractError`
- Domain: common
- Status: reserved
- Retry: after-operator-action
- Cause: Reserved for the pause rejection. A paused protocol is currently reported by the proof registry as 304, not as this code.
- Remediation: Poll is_paused rather than waiting for this code: a paused protocol surfaces as 304 in the current release. Treat both as the same operator-action outcome.
- Suggested HTTP status: 503
- Client message: "Service temporarily paused"

### 200 - `IssuerAlreadyRegistered`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: never
- Cause: register_issuer was called with an issuer_id_hash that already has a record.
- Remediation: Use update_issuer to change metadata, or rotate_issuer_address to change the address. Registration is one-time per identifier.
- Suggested HTTP status: 409
- Client message: "Issuer already registered"

### 201 - `IssuerNotFound`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: after-caller-change
- Cause: A call referenced an issuer_id_hash with no record, or the registry has no admin yet.
- Remediation: Register the issuer first, or confirm the identifier hash. If the registry is uninitialized, every call returns this code until an admin is set.
- Suggested HTTP status: 404
- Client message: "Issuer not found"

### 202 - `IssuerAddressAlreadyRegistered`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: never
- Cause: A registration or rotation targeted a Stellar address already bound to an issuer.
- Remediation: Choose an unused address. An address maps to at most one issuer so that address-based lookups stay unambiguous.
- Suggested HTTP status: 409
- Client message: "Issuer address already registered"

### 203 - `IssuerAddressNotFound`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: after-caller-change
- Cause: An address lookup found no entry in the reverse index.
- Remediation: The address is not a registered issuer. Note that a rotated-away address returns this code, because the old index entry is removed.
- Suggested HTTP status: 404
- Client message: "Issuer address not found"

### 204 - `IssuerRevoked`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: never
- Cause: The operation targeted an issuer whose status is Revoked.
- Remediation: Revocation is terminal. Register a new issuer identifier if the party is to be readmitted.
- Suggested HTTP status: 403
- Client message: "Issuer has been revoked"

### 205 - `IssuerInactive`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: reserved
- Retry: after-operator-action
- Cause: Reserved for the suspended-issuer rejection. A suspended issuer is now properly reported by the proof registry as 308, not as this code.
- Remediation: Call is_active_address before registering. An admin must reactivate the issuer; suspension is reversible, revocation is not.
- Suggested HTTP status: 403
- Client message: "Issuer is not active"

### 206 - `InvalidTransition`

- Enum: `IssuerError`
- Domain: issuer-registry
- Status: returned
- Retry: never
- Cause: A status change was requested that the lifecycle does not allow, such as reactivating a revoked issuer.
- Remediation: Read the current status and choose a permitted transition.
- Suggested HTTP status: 400
- Client message: "Invalid status transition"

### 300 - `ProofAlreadyRegistered`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: never
- Cause: register_proof was called with a proof_id_hash that already has a record.
- Remediation: Proof records are immutable once written, including after archival and restoration. Register a new identifier rather than replacing a commitment.
- Suggested HTTP status: 409
- Client message: "Proof already registered"

### 301 - `ProofNotFound`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-caller-change
- Cause: A call referenced a proof_id_hash with no record, or the proof registry has no instance state to read its dependencies from.
- Remediation: Confirm the identifier hash. If register_proof returns this code, the registry itself is uninitialized and no write took place.
- Suggested HTTP status: 404
- Client message: "Proof not found"

### 302 - `ProofAlreadyRevoked`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: never
- Cause: A revocation targeted a proof already in the Revoked state.
- Remediation: Treat the revocation as complete. Revocation is terminal and idempotent in effect, though not in return value.
- Suggested HTTP status: 400
- Client message: "Proof already revoked"

### 303 - `ProofExpired`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-caller-change
- Cause: register_proof was given an expires_at at or before the current ledger timestamp.
- Remediation: Send an expiration in the future relative to ledger time, not to wall-clock time on the calling host.
- Suggested HTTP status: 400
- Client message: "Invalid proof expiration"

### 304 - `InvalidSchemaVersion`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: never
- Cause: register_proof was given schema version zero.
- Remediation: Use a non-zero schema version. Schema version 0 is reserved and not allowed.
- Suggested HTTP status: 400
- Client message: "Invalid schema version"

### 305 - `SchemaVersionNotApproved`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-operator-action
- Cause: The schema version is non-zero but is not approved in protocol-config, either because it was never approved or because it was deprecated.
- Remediation: A protocol operator must approve the version. A registry pointed at an uninitialized protocol config also returns this code, because no version can be approved there.
- Suggested HTTP status: 400
- Client message: "Schema version not approved"

### 307 - `ContractPaused`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-operator-action
- Cause: The proof registry detected that the protocol is paused and rejected proof registration.
- Remediation: Call is_paused on the protocol config contract to check if the pause is active. An operator must unpause the protocol to allow proof registration to resume.
- Suggested HTTP status: 503
- Client message: "Contract is paused"

### 308 - `IssuerInactive`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-operator-action
- Cause: The issuer address is not active or was suspended.
- Remediation: Call is_active_address on the issuer registry to confirm the issuer is active. An operator must reactivate the issuer if it was suspended.
- Suggested HTTP status: 403
- Client message: "Issuer is not active"

### 309 - `UnsupportedSchema`

- Enum: `ProofError`
- Domain: proof-registry
- Status: returned
- Retry: after-operator-action
- Cause: The proof schema identifier is not supported or not registered in the protocol config.
- Remediation: Call is_schema_version_approved on the protocol config contract to verify the schema version is approved. An operator must approve the schema version before it can be used for proof registration.
- Suggested HTTP status: 400
- Client message: "Schema not supported"

### 310 - `MalformedInput`

- Enum: `ProofError`
- Domain: proof-registry
- Status: reserved
- Retry: after-caller-change
- Cause: Reserved for when proof input data fails format or size validation. No contract path currently returns this code; it is allocated so the code is never reused for a different meaning.
- Remediation: Validate the proof input data against the schema before resubmitting. Ensure all required fields are present and data sizes conform to the schema limits.
- Suggested HTTP status: 400
- Client message: "Malformed proof input"

<!-- END GENERATED -->
