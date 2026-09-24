# Contract Compatibility Golden Tests

This directory contains infrastructure for testing contract ABI and storage
compatibility. It prevents accidental breaking changes from reaching production
contracts and breaking downstream integrations.

## Structure

```
compatibility/
├── README.md                                   ← You are here
├── goldens/
│   ├── protocol-config.abi.json               ← Golden ABI snapshot
│   ├── issuer-registry.abi.json               ← Golden ABI snapshot
│   ├── proof-registry.abi.json                ← Golden ABI snapshot
│   └── negative-fixture.json                  ← Intentionally broken (test fixture)
└── (gate implementation will go here in PART 3)
```

## Golden ABI Files

Each `<contract>.abi.json` file is a **deterministic snapshot** of the contract's
public interface:

- **Functions**: exact signatures (parameters, order, types, return)
- **Types**: `#[contracttype]` struct/enum field shapes
- **Storage**: `DataKey` variants and value types
- **Events**: event topics and payload fields
- **Errors**: error code values

These files are maintained in version control. When contracts change, the golden
files are updated using `scripts/update-goldens.sh` and reviewed as part of the
commit diff.

## Updating Goldens

After making an intentional ABI or storage change to a contract:

```bash
./scripts/update-goldens.sh
```

This script:
1. Rebuilds all contracts for `wasm32-unknown-unknown`
2. Extracts ABI from each WASM using `stellar contract inspect`
3. Writes JSON snapshots to `tests/compatibility/goldens/`

Review the diffs carefully:

```bash
git diff tests/compatibility/goldens/
```

Then follow the checklist in `docs/GOLDEN_TEST_POLICY.md`:
- If only additions: merge directly
- If semantic changes: add release note, merge
- If breaking changes: version bump + migration + approval + release note

## Negative Fixture

`negative-fixture.json` contains **intentionally broken** schema with:
- Removed functions
- Removed struct fields  
- Changed storage types
- Removed events
- Changed error codes

This file is used to **validate the compatibility gate itself**. The gate
must reject any contract ABI that differs from its golden file in these ways.

**Do not use negative-fixture.json as a template for new contracts.**

## CI Gate

The compatibility gate (implemented in PART 3) will:

1. Read all golden files from this directory
2. Extract current contract ABIs from workspace
3. Compare and detect all differences
4. Classify as: additive, semantic, or breaking
5. **PASS** if:
   - Only additive changes, OR
   - Semantic/breaking changes have release note
6. **FAIL** with detailed diff if rules violated

See `docs/GOLDEN_TEST_POLICY.md` for full gate behavior and approval workflow.

## Adding a New Contract

When a new contract is added to the workspace:

1. Implement the contract normally
2. Run `./scripts/update-goldens.sh`
3. New golden file is created: `new-contract.abi.json`
4. Add it to version control
5. New contract is now subject to compatibility gates going forward

## Version History

| Version | Contracts | Date |
|---------|-----------|------|
| v0.1.0  | protocol-config, issuer-registry, proof-registry | Initial golden snapshots |

(As releases are cut, this table grows. See `docs/releases/` for details.)

## More Information

- **Policy**: `docs/GOLDEN_TEST_POLICY.md` — full rules, scenarios, approval workflow
- **Compatibility**: `docs/compatibility.md` — change classification and release requirements
- **Upgrades**: `docs/contract-upgrades.md` — how in-place WASM upgrades work
- **Update Script**: `scripts/update-goldens.sh` — maintains golden files

## Quick Reference: Change Classification

| Change | Class | Merge? |
|--------|-------|--------|
| New public function | Additive | ✅ Yes |
| New event | Additive | ✅ Yes |
| New storage key | Additive | ✅ Yes |
| Removed function | Breaking | ❌ No (needs approval) |
| Parameter added | Breaking | ❌ No (needs approval) |
| Storage field removed | Breaking | ❌ No (needs approval) |
| TTL constant changed | Semantic | ⚠️ Needs release note |
| New rejection condition | Semantic | ⚠️ Needs release note |

## Troubleshooting

**Q: `update-goldens.sh` says stellar CLI not available**

A: Install the stellar CLI from https://github.com/stellar/stellar-cli or update
the golden files manually by inspecting the contract ABI.

**Q: I see "GATE MUST FAIL" in negative-fixture.json**

A: That's intentional. The gate test verifies it detects those broken changes.
Don't use that file as a template.

**Q: Can I manually edit a golden file?**

A: Only to add documentation comments (lines starting with `//`). Always
regenerate the actual schema via `update-goldens.sh` to stay in sync.

**Q: The gate rejected my change but it's not breaking**

A: Check `docs/GOLDEN_TEST_POLICY.md` for the classification rules. If you
disagree, file an issue or reach out to maintainers. Gates can be overridden
with explicit sign-off in the release note.

