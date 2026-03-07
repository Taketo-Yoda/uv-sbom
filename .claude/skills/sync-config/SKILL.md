---
name: sync-config
description: Audit and fix CLI options that are missing from config file structs
---

# /sync-config - CLI-Config Sync Skill

Audits `src/cli.rs` against `src/config.rs` and `src/main.rs` to detect CLI options that are not exposed through the config file layer, and guides fixing any gaps found.

## Trigger Examples

- `/sync-config`
- "Check that all CLI options are reflected in the config file"
- "Verify CLI options are synced with config"

## Background: The Five-Location Rule

Every CLI option intended to be user-configurable must appear in **five places**:

| Location | What to add |
|----------|-------------|
| `src/config.rs` — `ConfigFile` struct | `pub <field>: Option<T>` |
| `src/config.rs` — `CONFIG_TEMPLATE` | Commented-out YAML entry with description |
| `src/main.rs` — `MergedConfig` struct | `<field>: T` |
| `src/main.rs` — `merge_config()` | CLI > config > default priority logic |
| `src/main.rs` — request builder | Pass merged value to `SbomRequest` |

## Reference Implementation: `check_cve`

Use `check_cve` as the canonical pattern when adding a new boolean flag:

**`src/config.rs` — `ConfigFile`**:
```rust
pub check_cve: Option<bool>,
```

**`src/config.rs` — `CONFIG_TEMPLATE`**:
```yaml
# Enable CVE vulnerability checking
# check_cve: false
```

**`src/main.rs` — `MergedConfig`**:
```rust
check_cve: bool,
```

**`src/main.rs` — `merge_config()`**:
```rust
// check_cve: CLI flag || config value
let check_cve = args.check_cve || config.check_cve.unwrap_or(false);
```

**`src/main.rs` — request builder**:
```rust
.check_cve(merged.check_cve)
```

## Workflow

### Step 1: Audit — Extract CLI Options

Read `src/cli.rs` and list all `pub` fields in the `Args` struct.

Exclude from audit (infrastructure, not user-configurable features):
- `config` (`-c` / `--config`) — selects the config file itself
- `init` (`--init`) — generates the config template
- `path` (`-p`) — project path
- `output` (`-o`) — output file path

### Step 2: Audit — Check `ConfigFile` Coverage

Read `src/config.rs` and list all fields in the `ConfigFile` struct (excluding `unknown_fields`).

Map CLI field names to config field names (they may differ):

| CLI field (`Args`) | Config field (`ConfigFile`) |
|--------------------|-----------------------------|
| `exclude` | `exclude_packages` |
| `ignore_cve` | `ignore_cves` |
| `license_allow` / `license_deny` | `license_policy` |
| others | same name |

Report any CLI options absent from `ConfigFile`.

### Step 3: Audit — Check `MergedConfig` Coverage

Read `src/main.rs` and list all fields in the `MergedConfig` struct.

Report any CLI options (that passed Step 2) absent from `MergedConfig`.

### Step 4: Audit — Check `CONFIG_TEMPLATE` Coverage

Read the `CONFIG_TEMPLATE` const in `src/config.rs`.

For each field in `ConfigFile`, verify a corresponding commented-out YAML entry exists.

Report any `ConfigFile` fields missing from the template.

### Step 5: Report Audit Results

Present a summary table:

```
CLI option       | ConfigFile | MergedConfig | CONFIG_TEMPLATE | Status
-----------------|------------|--------------|-----------------|--------
check_cve        | YES        | YES          | YES             | OK
suggest_fix      | NO         | NO           | NO              | MISSING
verify_links     | NO         | NO           | NO              | MISSING
```

If no gaps are found, report "All CLI options are reflected in config — no action needed."

### Step 6: Fix (if gaps found)

For each missing option, implement all required locations following the reference pattern:

1. Add `pub <field>: Option<T>` to `ConfigFile` in `src/config.rs`
2. Add commented-out YAML entry to `CONFIG_TEMPLATE` in `src/config.rs`
3. Add `<field>: T` to `MergedConfig` in `src/main.rs`
4. Add merge logic to `merge_config()` in `src/main.rs`
5. Wire the merged value into `SbomRequest` in the request builder

**Priority rule for booleans**: `CLI flag || config.field.unwrap_or(false)`

**Priority rule for Options**: `args.field.or(config.field)`

### Step 7: Test

After fixing, ensure `merge_config` logic is covered by unit tests:

- Test: CLI flag enabled, config absent → value is `true`
- Test: CLI flag absent, config enabled → value is `true`
- Test: Both absent → default applies

Run tests:
```bash
cargo test --lib merge_config
```

### Step 8: Verify

```bash
cargo fmt --all -- --check
cargo clippy -- -D warnings
cargo test
```

If any check fails, fix before committing.

## Notes

- `suggest_fix` and `verify_links` are intentionally CLI-only as of PR #275 — confirm with user before adding config support
- Boolean flags default to `false`; Option fields default to `None`
- `CONFIG_TEMPLATE` must remain valid YAML when uncommented (verified by `test_template_is_valid_yaml_when_uncommented`)
