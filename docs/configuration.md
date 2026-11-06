# Configuration

[Back to README](../README.md)

uv-sbom supports a YAML configuration file (`uv-sbom.config.yml`) for setting default options, package exclusion patterns, CVE ignore lists, and license policies. CLI arguments always override config file values.

## Table of Contents

- [Configuration File](#configuration-file)
- [Config File Schema Reference](#config-file-schema-reference)
- [Priority and Merge Rules](#priority-and-merge-rules)
- [Excluding Packages](#excluding-packages)
- [Excluding Packages by Dependency Group](#excluding-packages-by-dependency-group)
- [Ignoring Specific CVEs](#ignoring-specific-cves)
- [Validating Configuration with Dry-Run](#validating-configuration-with-dry-run)

---

## Configuration File

You can use a configuration file (`uv-sbom.config.yml`) to set default options instead of passing them on the command line every time.

### Generating a Config Template

Use the `--init` option to generate a template configuration file with all available fields as commented examples:

```bash
# Generate template in the current directory
uv-sbom --init

# Generate template in a specific directory
uv-sbom --init --path ./my-project
```

This creates a `uv-sbom.config.yml` file with inline documentation for every option. If the file already exists, the command exits with an error to prevent accidental overwriting.

**Auto-discovery**: Place a `uv-sbom.config.yml` file in your project directory (where `uv.lock` is located). The tool automatically detects and loads it.

**Explicit path**: Use `--config` / `-c` to specify a config file at a custom location.

```bash
# Auto-discovered config file (place in project directory)
uv-sbom

# Explicit config file path
uv-sbom --config ./custom-config.yml
```

**Example configuration file** (`uv-sbom.config.yml`):

```yaml
# Output format: json, markdown, or md
format: markdown

# Packages to exclude from SBOM (supports wildcards)
exclude_packages:
  - "pytest"
  - "mypy"
  - "*-dev"

# Enable CVE vulnerability checking
check_cve: true

# Severity threshold for vulnerability check (low/medium/high/critical)
severity_threshold: high

# CVSS threshold for vulnerability check (0.0-10.0)
# cvss_threshold: 7.0

# CVEs to ignore (with optional reason)
ignore_cves:
  - id: CVE-2024-1234
    reason: "False positive for our use case"
  - id: CVE-2024-5678
    reason: "Mitigated by network configuration"

# License compliance policy
license_policy:
  allow: ["MIT", "Apache-2.0", "BSD-*", "ISC", "PSF-2.0"]
  deny: ["GPL-3.0-only", "GPL-3.0-or-later", "AGPL-*"]
  unknown: "warn"  # "warn" | "deny" | "allow"

# Enrich CVE results with EPSS scores and CISA KEV status
# check_exploitability: false

# Path to vulnerability baseline file for suppressing previously-accepted CVE findings
# baseline_file: .uv-sbom-baseline.json
```

## Config File Schema Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | string | No | Output format (`json` / `markdown` / `md`). Any other value is a config error (exit code `3`) |
| `exclude_packages` | string[] | No | Package exclusion patterns (supports wildcards) |
| `check_cve` | bool | No | Override CVE checking behavior. Defaults to true when unset |
| `severity_threshold` | string | No | Severity threshold (`low` / `medium` / `high` / `critical`) |
| `cvss_threshold` | number | No | CVSS threshold (0.0 - 10.0) |
| `ignore_cves` | object[] | No | List of CVEs to ignore |
| `ignore_cves[].id` | string | Yes | CVE ID (e.g., `CVE-2024-1234`) |
| `ignore_cves[].reason` | string | No | Reason for ignoring |
| `license_policy` | object | No | License compliance policy configuration |
| `license_policy.allow` | string[] | No | Allowed license patterns (supports wildcards) |
| `license_policy.deny` | string[] | No | Denied license patterns (supports wildcards) |
| `license_policy.unknown` | string | No | Unknown license handling (`warn` / `deny` / `allow`) |
| `check_abandoned` | bool | No | Enable abandoned package detection (opt-in, default: false) |
| `abandoned_threshold_days` | integer | No | Inactivity threshold in days for abandoned package detection (default: 730) |
| `check_non_pypi` | bool | No | Enable non-PyPI source detection (opt-in, default: false) |
| `exclude_groups` | string[] | No | Dependency groups whose exclusively-reachable packages are excluded from the SBOM |
| `check_exploitability` | bool | No | Enrich CVE results with EPSS scores and CISA KEV status (opt-in, default: false) |
| `target_python` | string | No | Target Python version for compatibility checking (PEP 440 format, e.g. `"3.8"`). Unset disables the check |
| `baseline_file` | string | No | Path to a vulnerability baseline JSON file for suppressing previously-accepted findings |

## Priority and Merge Rules

- **`format` validation**: Accepted values are `json`, `markdown`, and `md` (case-insensitive). Any other value causes a config error and the tool exits with code `3`. The error message is: `Invalid config: format must be one of: json, markdown. Got: "<value>"`
- **CLI arguments override config file values** for scalar fields (`format`, `severity_threshold`, `cvss_threshold`). An explicit `--format json` also overrides a config `format: markdown`
- **`check_cve`** defaults to true when unset. Set to false in config to disable. Use --no-check-cve CLI flag to opt out
- **`exclude_packages`** are **merged** from both CLI and config file, then deduplicated
- **`ignore_cves`** are **merged** from both CLI (`--ignore-cve`) and config file, deduplicated by ID (CLI entry takes precedence for duplicates)
- **`check_license`** is enabled if set via CLI flag OR config file (logical OR, same as `check_cve`)
- **`--license-allow`** and **`--license-deny`** CLI options **override** config file `license_policy.allow` / `license_policy.deny` entirely (not merged)
- **`check_abandoned`** is opt-in (default: false). Enable via CLI flag `--check-abandoned` or config file `check_abandoned: true`. The `abandoned_threshold_days` value follows CLI > config file > default (730) resolution order.
- **`check_non_pypi`** is opt-in (default: false). Enable via CLI flag `--check-non-pypi` or config file `check_non_pypi: true`.
- **`check_exploitability`** is opt-in (default: false). Enable via CLI flag `--check-exploitability` or config file `check_exploitability: true`. Requires CVE checking (conflicts with `--no-check-cve`).
- **`exclude_groups`**: CLI `--exclude-groups` **overrides** the config file value entirely (not merged). `--production-only` resolves all group names from the lockfile at runtime and takes precedence over both CLI and config.
- **`target_python`** is opt-in (default: unset, no check performed). Enable via CLI flag `--target-python 3.8` or config file `target_python: "3.8"`. CLI value takes precedence over the config file.

## Excluding Packages

You can exclude specific packages from the SBOM using the `--exclude` or `-e` option:

```bash
# Exclude a single package
uv-sbom -e "pytest"

# Exclude multiple packages
uv-sbom -e "pytest" -e "mypy" -e "black"

# Use wildcards to exclude patterns
uv-sbom -e "debug-*"        # Exclude all packages starting with "debug-"
uv-sbom -e "*-dev"          # Exclude all packages ending with "-dev"
uv-sbom -e "*-test-*"       # Exclude all packages containing "-test-"

# Combine with other options
uv-sbom --format json --output sbom.json -e "pytest" -e "*-dev"
```

**Pattern Syntax:**
- Use `*` as a wildcard to match zero or more characters
- Patterns are case-sensitive
- Maximum 64 patterns per invocation

**Preventing Information Leakage:**
Use the `--exclude` option to skip specific internal or proprietary libraries. This prevents their names from being sent to external registries (like PyPI) during metadata retrieval, ensuring your internal project structure remains private.

## Excluding Packages by Dependency Group

Use `--exclude-groups` to exclude packages that are **exclusively reachable** through specified [dependency groups](https://docs.astral.sh/uv/concepts/dependencies/#dependency-groups) (e.g., `dev`, `test`, `lint`). Packages shared with production dependencies are always retained. Group names are matched case- and separator-insensitively ([PEP 735](https://peps.python.org/pep-0735/)), so `--exclude-groups Lint` or `--exclude-groups type_check` excludes the groups `lint` and `type-check`; the same applies to `exclude_groups` in the config file.

```bash
# Exclude packages only reachable via the "dev" group
uv-sbom --exclude-groups dev --format markdown

# Exclude multiple groups (comma-separated)
uv-sbom --exclude-groups dev,test,lint --format markdown

# Production-only mode: exclude ALL non-default dependency groups automatically
uv-sbom --production-only --format markdown
```

`--production-only` reads the `[manifest.dependency-groups]` section of your `uv.lock` file at runtime and sets `--exclude-groups` to every group it finds. This is equivalent to listing all groups explicitly but is more concise and automatically adapts as groups are added or removed.

> **Note:** `--exclude-groups` and `--production-only` are mutually exclusive.

You can also set this in the config file:

```yaml
# Exclude packages reachable only through these dependency groups
exclude_groups:
  - dev
  - test
  - lint
```

## Ignoring Specific CVEs

You can ignore specific CVEs from the command line using `--ignore-cve` / `-i`:

```bash
# Ignore specific CVEs from CLI
uv-sbom --ignore-cve CVE-2024-1234 --ignore-cve CVE-2024-5678

# Short form
uv-sbom -i CVE-2024-1234 -i CVE-2024-5678

# Combine config file and CLI ignores (both sources are merged)
uv-sbom --config ./config.yml -i CVE-2024-9999
```

## Validating Configuration with Dry-Run

Use the `--dry-run` option to validate your configuration before the tool communicates with external registries:

```bash
# Verify exclude patterns work correctly
uv-sbom --dry-run -e "internal-*" -e "proprietary-pkg"

# Test configuration with all options
uv-sbom --dry-run --path /path/to/project --format json -e "*-dev"
```

**Why use --dry-run:**
- **Verify exclude patterns**: Ensure your `--exclude` patterns correctly match the packages you want to skip
- **Prevent information leakage**: Confirm that sensitive internal packages are excluded BEFORE the tool communicates with PyPI registry
- **Fast validation**: All input validation happens without network overhead
- **Early error detection**: Catch configuration issues (missing uv.lock, invalid patterns, etc.) immediately

**What happens in dry-run mode:**
- ✅ Reads and parses `uv.lock` file
- ✅ Validates all command-line arguments
- ✅ Checks exclude patterns and warns about unmatched patterns
- ✅ Outputs success message if no issues found
- ❌ Skips license fetching from PyPI (no network communication)
- ❌ Skips SBOM output generation
