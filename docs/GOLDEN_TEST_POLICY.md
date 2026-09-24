# Contract ABI and Storage Compatibility Golden Tests

## Overview

Contract ABI and storage compatibility is gated by golden tests in
`tests/compatibility/goldens/`. These tests prevent accidental breaking changes
from reaching deployed contracts and causing failures in downstream clients
(backend, indexers, other integrations).

Golden tests are **deterministic snapshots** of the contract's public interface:
every function signature, storage key, event topic, and error code. They are
maintained in version control and validated by CI before every merge.

## What Is Covered

Each contract has one golden ABI file (`<contract>.abi.json`) recording:

- **Public functions**: exact signatures (parameters, order, types, return type)
- **Stored types**: `#[contracttype]` struct and enum fields/variants
- **Storage keys**: `#[contracttype] enum DataKey` variants and value types
- **Events**: `#[contractevent]` topics and payload field types
- **Error codes**: `#[contracterror]` enum values (numeric codes must not change)
- **Cross-contract calls**: trait signatures for external contract dependencies

## CI Compatibility Gates

### 1. Additive Changes (No Approval Required)

These are backwards-compatible and may be deployed without special review:

- **New public functions** — existing callers unaffected
- **New event topics** — indexers may ignore unknown events
- **New event payload fields** — indexers ignoring unknown fields stay compatible
- **New storage key variants** — old code paths unaffected
- **New error codes** (with higher numeric values) — old error handler ranges unaffected

**CI gate**: ✅ PASS (no special action needed; direct merge allowed)

### 2. Semantic Changes (Release Note Required)

These change behavior without changing the interface. They require explicit
documentation in the release note for consumers to retest affected flows:

- **TTL constant changes** — changes to ledger extension thresholds
- **New rejection condition** — previously accepted calls now fail (ProofError::InvalidSchemaVersion was added)
- **Authorization relaxation** — an admin-only function becomes public
- **Panic message changes** — strings are not a stable interface, only added as informational

**CI gate**: ⚠️ WARN (detects change, passes if release note present)

### 3. Breaking Changes (Full Governance Required)

These require version bump, migration strategy, and explicit approval before
deployment to any shared network:

- **Function signature changed** — parameter added, removed, reordered, or type changed
- **Function removed or renamed** — existing callers break at invocation time
- **Storage field added to struct** — old stored entries fail to deserialize (no migration hook exists)
- **Storage key variant removed** — old data becomes inaccessible
- **Event topic removed or field removed** — indexers depending on these break
- **Error code value changed** — exception handlers targeting old code fail
- **Authorization tightened** — previously authorized caller now rejected

**CI gate**: ❌ FAIL (gates the build; requires explicit approval in release note)

## How to Update Goldens After Intentional Changes

### Step 1: Make the Code Change

Modify the contract code as needed (add function, remove parameter, etc.).

### Step 2: Run the Update Script

```bash
./scripts/update-goldens.sh
```

This:
1. Rebuilds all contracts for `wasm32-unknown-unknown`
2. Extracts the ABI from each WASM using `stellar contract inspect`
3. Writes JSON snapshots to `tests/compatibility/goldens/`
4. Reports any failures (e.g., stellar CLI not available)

### Step 3: Review the Diff

```bash
git diff tests/compatibility/goldens/
```

Identify what changed:
- Are these additions only? (Go to merge.)
- Are these semantic changes? (Add release note, go to merge.)
- Are these breaking changes? (Proceed to Step 4.)

### Step 4: Document Breaking Changes

Create or update the release note in `docs/releases/<version>.md`:

```yaml
release: v0.2.0
date: 2026-01-15
commit: abc123def456...
toolchain: 1.98.0 (soroban-sdk 27.0.0)
contracts:
  - name: protocol-config
    version: 0.2.0
    wasm_sha256: deadbeef...

changes:
  - class: Breaking
    what: "Removed 'approve_schema_version' function"
    why: "Consolidating all schema governance into ProtocolConfig.gate_schema()"
    impact: "Backend must use gate_schema() instead; existing approvals unaffected"

  - class: Breaking
    what: "Changed DataKey::SchemaVersion storage value type from bool to u32"
    why: "Recording approval timestamp in addition to boolean status"
    impact: "Stored state incompatible; requires new contract ID and off-chain data migration"

migration: |
  1. Deploy new protocol-config contract to fresh ID
  2. Re-approve schema versions in new contract
  3. Update backend references from old to new contract ID
  4. Re-notify existing issuers of new reference
  5. Old contract ID may be deprecated after grace period

backend_compatibility: "v2.1.0 or later (v2.0.x uses removed functions)"

rollback: |
  If gate_schema() misbehaves, redeploy v0.1.0 to the old contract ID
  (state is compatible). Backend reverts to v0.1.0 behavior.
  No operator action needed; downgrade is zero-cost.

approvals:
  - maintainer: Alice (alice@example.com)
    date: 2026-01-10
    note: "Reviewed and approved for breaking storage change. Migration is atomic."
```

### Step 5: Commit and Push

```bash
git add -A
git commit -m "v0.2.0: Remove approve_schema_version, consolidate to gate_schema()

Breaking changes:
- Removed public function approve_schema_version (use gate_schema)
- Changed DataKey::SchemaVersion storage type (bool → u32)
- Stored state is NOT compatible; new contract ID required

See docs/releases/v0.2.0.md for migration steps and backend compatibility notes.
"
git push origin feature/gate-schema-consolidation
```

### Step 6: CI Validation

The CI pipeline:
1. Extracts ABI from your WASM
2. Compares to golden files
3. Detects all breaking changes
4. Verifies that the release note exists and is complete
5. **Blocks the build if breaking changes lack required documentation**

## Negative Fixture and Gate Validation

`tests/compatibility/goldens/negative-fixture.json` is an **intentionally broken**
golden file containing removed functions, changed storage types, and deleted events.

**The gate must reject this file.** If the gate passes against it, the gate is
broken and must be fixed before any merge.

### Validating the Gate Itself

```bash
# After implementing the gate, run:
cargo test --test compatibility_gate -- --nocapture

# Expected: test should detect that negative-fixture.json contains:
#   - Removed function: removed_function_that_no_longer_exists
#   - Removed storage key: DataKey::RemovedStorageKey
#   - Removed event: RemovedEventTopic
#   - And more...
#
# If test passes, the gate is working correctly.
```

## Golden Files: Structure and Naming

All golden files live in `tests/compatibility/goldens/`:

```
tests/compatibility/
├── goldens/
│   ├── protocol-config.abi.json        ← Protocol config golden
│   ├── issuer-registry.abi.json        ← Issuer registry golden
│   ├── proof-registry.abi.json         ← Proof registry golden
│   └── negative-fixture.json           ← Intentionally broken (test only)
└── (future: test code for the gate itself)
```

### Schema (`$schema` field)

All golden files validate against `earnproof-contract-abi/v1`. This schema:
- Documents all required fields
- Validates that `contract`, `soroban_sdk_version`, `functions`, `types`, `errors`, `events`, `storage` are present
- Rejects files missing critical metadata

### Metadata Fields

Every golden file has:
- **`contract`**: Exact struct name from `#[contract] pub struct ContractName`
- **`soroban_sdk_version`**: From workspace Cargo.toml (27.0.0)
- **`rust_toolchain`**: From rust-toolchain.toml (1.98.0)
- **`generated_from`**: "Part 1 analysis" or "stellar contract inspect" or "manual update"
- **`note`**: Instructions for maintainers

## Breaking Change Classification

### ABI (Entry Points)

| Change | Class |
|--------|-------|
| Adding a new entry point | **Additive** |
| Adding a parameter | **Breaking** |
| Removing a parameter | **Breaking** |
| Reordering parameters | **Breaking** |
| Changing a parameter type | **Breaking** |
| Changing return type | **Breaking** |
| Removing entry point | **Breaking** |

### Storage

| Change | Class |
|--------|-------|
| Adding a key variant | **Additive** |
| Adding a field to stored struct | **Breaking** (no migration) |
| Removing a key variant | **Breaking** |
| Changing a stored type | **Breaking** |
| Changing TTL constant | **Semantic** |

### Events

| Change | Class |
|--------|-------|
| Adding new event | **Additive** |
| Adding event payload field | **Additive** (backwards-compatible) |
| Removing event | **Breaking** |
| Removing event field | **Breaking** |
| Changing field type | **Breaking** |

### Errors

| Change | Class |
|--------|-------|
| Adding new error variant | **Additive** (if higher code) |
| Removing error variant | **Semantic** (previously rejected calls now accepted) |
| Changing error code value | **Breaking** |
| Adding rejection condition | **Semantic** |

## Testing the Gate

The gate is implemented as a Rust test in `tests/compatibility/` (created in PART 3).

It will:
1. Read all golden files from `tests/compatibility/goldens/`
2. Parse current contract ABIs (from workspace Cargo.toml)
3. Compare golden vs. current for each contract
4. Report all differences (additions, removals, changes)
5. Classify each difference by class (additive, semantic, breaking)
6. Pass if:
   - Only additive changes exist, OR
   - Semantic changes exist but release note found, OR
   - Breaking changes exist AND release note covers all of them
7. Fail with detailed diff if rules violated

## Integration with CI/CD

### GitHub Actions Workflow

The CI job `compatibility-gate` (added to `.github/workflows/ci.yml`):

```yaml
compatibility-gate:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@1.98.0
    - run: cargo test --test compatibility_gate -- --nocapture
```

Runs after contracts build succeeds. Blocks merge if gate fails.

### When Merging PRs

1. Developer makes ABI change
2. Runs `./scripts/update-goldens.sh` locally
3. Commits golden updates + version bump + release note
4. Pushes PR
5. CI runs compatibility gate
6. If breaking changes but no release note: **CI FAILS** (blocks merge)
7. Developer updates release note or reverts change
8. CI reruns and passes
9. Merge approved

## Common Scenarios

### Scenario 1: Adding a New Query Function

**Code change**: New `pub fn is_approved_issuer(env: Env, id: BytesN<32>) -> bool`

**Golden change**: New entry in `functions[]` array

**Gate result**: ✅ PASS (additive)

**Action**: Merge directly; no release note needed

---

### Scenario 2: Renaming a Parameter

**Code change**: `register_issuer(..., issuer_id_hash: ...)` → `register_issuer(..., issuer_hash: ...)`

**Golden change**: `"name": "issuer_id_hash"` → `"name": "issuer_hash"`

**Gate result**: ❌ FAIL (parameter name changed; could break named-arg callers)

**Action**: Either revert parameter name, or add breaking change to release note + version bump

---

### Scenario 3: Adding a Field to IssuerRecord

**Code change**: Add `pub metadata_version: u32` field to `#[contracttype] IssuerRecord`

**Golden change**: New field in `types[IssuerRecord].fields[]`

**Gate result**: ❌ FAIL (breaking storage change)

**Why**: Old stored records were serialized without this field. Deserialization fails.

**Action**: Add breaking change to release note + version bump + migration strategy:
- Option A: New contract ID + off-chain data export/reimport
- Option B: Custom deserialization (if Soroban SDK supports it)

---

### Scenario 4: Adding a New Event Field

**Code change**: `IssuerRegistered` gains new optional field: `metadata_version: u32`

**Golden change**: New field in `events[IssuerRegistered].data_type`

**Gate result**: ✅ PASS (additive event field)

**Why**: Indexers ignoring unknown fields remain compatible; old events have `null` for new field

**Action**: Merge directly; no release note needed

---

## Maintenance and Versioning

### Version Scheme

Contracts follow semver, interpreted against compatibility classes:

- **Patch** (0.1.0 → 0.1.1): Additive changes only
- **Minor** (0.1.0 → 0.2.0): Semantic changes (behavioral, not interface)
- **Major** (0.1.0 → 1.0.0): Any breaking change

### Updating Golden Files

All golden updates must go through `./scripts/update-goldens.sh`:

```bash
# Make your code change
# Then:
./scripts/update-goldens.sh

# Review:
git diff tests/compatibility/goldens/

# If breaking:
# 1. Edit docs/releases/v<version>.md
# 2. Add version bump to contracts/*/Cargo.toml
# 3. Commit everything
```

**Never manually edit golden files** (except to add metadata comments or fix errors).
Always regenerate via the script to ensure exact sync with built artifacts.

### Breaking Changes and Rollback

For **breaking storage changes**:
- Old contract ID cannot be downgraded safely (state incompatible)
- Rollback requires deploying v-1 to **new** contract ID
- All consumers must re-point to new ID
- Off-chain data may need export/reimport

For **breaking ABI-only changes** (storage compatible):
- Old contract ID can be downgraded via in-place upgrade
- Rollback is transparent to consumers
- Old WASM binary must be kept for downgrade

See [docs/contract-upgrades.md](contract-upgrades.md) for upgrade mechanics.

## Approval and Sign-Off

Any breaking change requires:

1. **Maintainer approval** (name + date in release note)
2. **Migration plan** (explicit steps or "none")
3. **Rollback plan** (how to revert or why impossible)
4. **Containment notes** (operator action if misbehavior in production)

See [docs/compatibility.md](compatibility.md) for the full governance model.

## FAQ

**Q: Can I update a golden file manually?**  
A: Only to add documentation comments. Always regenerate the file via `update-goldens.sh`
to ensure sync with built artifacts. Manual edits risk desync and subtle bugs.

**Q: What if stellar CLI is not available?**  
A: `update-goldens.sh` will warn you. You can manually inspect the contract ABI
and update the JSON, or wait for CI to provide it. For local development, install
the stellar CLI: https://github.com/stellar/stellar-cli

**Q: Do golden files need to be in every commit?**  
A: Only if the contracts changed. If you only modify tests or docs, don't touch
`tests/compatibility/goldens/`. The gate will skip unchanged contracts.

**Q: Can I have multiple breaking changes in one release?**  
A: Yes. Document each in `docs/releases/<version>.md` under `changes[]` with its
class and rationale. The gate verifies all are documented.

**Q: What if the gate incorrectly rejects a valid change?**  
A: The gate logic is in `tests/compatibility/` and visible to all. File an issue
with the specific false positive, and maintainers will review the classification
rules. Until fixed, you can override with explicit approval in the release note
(but this requires maintainer sign-off).

