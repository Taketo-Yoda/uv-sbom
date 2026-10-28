# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql)

[English](README.md) | [日本語](README-JP.md)

----

Generate SBOMs (Software Bill of Materials) for Python projects managed by [uv](https://github.com/astral-sh/uv).

## Features

- 📦 Parses `uv.lock` files to extract dependency information
- 🔍 Automatically fetches license information from PyPI with retry logic
- 🛡️ Checks for known vulnerabilities using OSV API (Markdown format only)
- 📋 License compliance policy check with configurable allow/deny lists and wildcard support
- 🔎 **Vulnerability Resolution Guide** - Identifies which direct dependency introduces each vulnerable transitive package, and shows the **full dependency chain** for multi-hop transitive vulnerabilities
- 📊 Outputs in multiple formats:
  - **CycloneDX 1.6** JSON format (standard SBOM format)
  - **Markdown** format with direct and transitive dependencies clearly separated
- 🔍 **Abandoned Package Detection** - Identifies packages that have not received a new release on PyPI within a configurable number of days (default: 730), helping surface unmaintained dependencies with no active security patching
- 🚀 Fast and standalone - written in Rust
- 💾 Output to stdout or file
- 🛡️ Robust error handling with helpful error messages and suggestions
- 📈 Progress tracking during license information retrieval
- 🎯 **Exploitability Prioritization** - Enriches CVE results with EPSS scores (FIRST.org) and CISA KEV catalog status, helping prioritize vulnerabilities by real-world exploitation likelihood

## Scope and Key Differences from CycloneDX

### SBOM Scope

This tool generates SBOMs based on **uv.lock** file contents, which includes:
- Direct runtime dependencies
- Transitive runtime dependencies
- Development dependencies (if locked in uv.lock)

**What's NOT included:**
- Build system dependencies (e.g., hatchling, setuptools)
- Publishing tools (e.g., twine, build)
- Dependencies only present in the virtual environment but not locked in uv.lock

### Comparison with CycloneDX Official Tools

As of v7.2.1, the official cyclonedx-python library does not yet provide direct support for uv. When generating SBOMs for Python projects:

| Aspect | uv-sbom (this tool) | CycloneDX Official Tools |
|--------|---------------------|--------------------------|
| **Data Source** | `uv.lock` file | `.venv` virtual environment |
| **Scope** | Production runtime dependencies only | Entire supply chain including build/dev tools |
| **Package Count** | Typically fewer (e.g., 16 packages) | Typically more (e.g., 38+ packages) |
| **Use Case** | Production security scanning | Comprehensive supply chain audit |
| **Accuracy** | Reflects locked dependencies | Reflects installed packages |

### Which Tool Should You Use?

- **For production security scanning**: Use `uv-sbom` to focus on dependencies that will be deployed to production
- **For comprehensive supply chain audit**: Use CycloneDX official tools to include all development and build-time dependencies
- **For regulatory compliance**: Check your specific requirements - some regulations may require the comprehensive approach

The focused approach of `uv-sbom` reduces noise in security vulnerability scanning by excluding build-time dependencies that don't ship with the final application.

## Installation

### Cargo (Recommended for Rust users)

![Crates.io Total Downloads](https://img.shields.io/crates/d/uv-sbom)

Install from [crates.io](https://crates.io/crates/uv-sbom):

```bash
cargo install uv-sbom
```

### uv tool (Python users)

![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=PyPI&logoColor=white)

Install the Python wrapper package:

```bash
uv tool install uv-sbom-bin
```

Or via pip:

```bash
pip install uv-sbom-bin
```

After installation, use the `uv-sbom` command:

```bash
uv-sbom --version
```

**Note**: The package name is `uv-sbom-bin`, but the installed command is `uv-sbom`.

### Pre-built Binaries

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/Taketo-Yoda/uv-sbom/total?logo=GitHub)


Download pre-built binaries from [GitHub Releases](https://github.com/Taketo-Yoda/uv-sbom/releases):

**macOS (Apple Silicon)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-aarch64-apple-darwin.tar.gz
tar xzf uv-sbom-aarch64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**macOS (Intel)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-apple-darwin.tar.gz
tar xzf uv-sbom-x86_64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Linux (x86_64)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-unknown-linux-gnu.tar.gz
tar xzf uv-sbom-x86_64-unknown-linux-gnu.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Windows**:
Download `uv-sbom-x86_64-pc-windows-msvc.zip` from the [releases page](https://github.com/Taketo-Yoda/uv-sbom/releases) and extract to your desired location.

### From Source

```bash
# Clone the repository
git clone https://github.com/Taketo-Yoda/uv-sbom.git
cd uv-sbom

# Build and install
cargo build --release
cargo install --path .
```

### Verify Installation

```bash
uv-sbom --version
```

## Usage

### Basic usage

Generate a CycloneDX JSON SBOM for the current directory:

```bash
uv-sbom
```

### Output formats

Generate a Markdown table with direct and transitive dependencies:

```bash
uv-sbom --format markdown
```

Generate a CycloneDX JSON (default):

```bash
uv-sbom --format json
```

### Output language

Use the `--lang` option to switch the output language for human-readable formats (Markdown). The default is English (`en`).

```bash
# Generate a Japanese Markdown SBOM report
uv-sbom --format markdown --lang ja

# Generate an English Markdown SBOM report (default)
uv-sbom --format markdown --lang en
```

**Supported values:** `en` (English, default), `ja` (Japanese)

**Note:** The `--lang` option affects section headers, table column names, and status labels in Markdown output. Package names, CVE IDs, and SPDX license identifiers always remain in their original form regardless of `--lang`.

### Specify project path

Analyze a project in a different directory:

```bash
uv-sbom --path /path/to/project
```

### Save to file

Output to a file instead of stdout:

```bash
uv-sbom --format json --output sbom.json
uv-sbom --format markdown --output SBOM.md
```

### Combined options

```bash
uv-sbom --path /path/to/project --format markdown --output SBOM.md
```

### Excluding packages

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

### Excluding packages by dependency group

Use `--exclude-groups` to exclude packages that are **exclusively reachable** through specified [dependency groups](https://docs.astral.sh/uv/concepts/dependencies/#dependency-groups) (e.g., `dev`, `test`, `lint`). Packages shared with production dependencies are always retained.

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

### Configuration file

You can use a configuration file (`uv-sbom.config.yml`) to set default options instead of passing them on the command line every time.

#### Generating a config template

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
# Output format: json or markdown
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

#### Config File Schema Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | string | No | Output format (`json` / `markdown`) |
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

#### Priority and Merge Rules

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

### Ignoring specific CVEs

You can ignore specific CVEs from the command line using `--ignore-cve` / `-i`:

```bash
# Ignore specific CVEs from CLI
uv-sbom --ignore-cve CVE-2024-1234 --ignore-cve CVE-2024-5678

# Short form
uv-sbom -i CVE-2024-1234 -i CVE-2024-5678

# Combine config file and CLI ignores (both sources are merged)
uv-sbom --config ./config.yml -i CVE-2024-9999
```

### Checking for vulnerabilities

CVE vulnerability checking is **enabled by default** using the [OSV (Open Source Vulnerability) database](https://osv.dev). No flag is required:

```bash
# Check for vulnerabilities in Markdown output (CVE check runs automatically)
uv-sbom --format markdown

# Save vulnerability report to file
uv-sbom --format markdown --output SBOM.md

# Combine with exclude patterns
uv-sbom --format markdown -e "pytest" -e "*-dev"

# Opt out of CVE checking
uv-sbom --format markdown --no-check-cve
```

### Disabling CVE Checking

CVE vulnerability checking is enabled by default. To opt out, use the `--no-check-cve` flag:

```bash
# Generate SBOM without CVE checking
uv-sbom --format markdown --no-check-cve

# Disable via config file
# check_cve: false  (in uv-sbom.config.yml)
```

> **Note:** `--no-check-cve` conflicts with `--severity-threshold`, `--cvss-threshold`, and `--suggest-fix`.

### License Compliance Check

Use the `--check-license` option to check packages against a configurable license policy:

```bash
# Enable license compliance check (using config file policy)
uv-sbom --check-license --format markdown

# With inline policy (overrides config file)
uv-sbom --check-license --license-allow "MIT,Apache-2.0,BSD-*" --license-deny "GPL-3.0,AGPL-*"

# Combined with vulnerability check
uv-sbom --check-license --severity-threshold high
```

**How it works:**
- **Deny takes precedence over allow**: If a license matches both lists, it is denied
- **Wildcard patterns**: Use `BSD-*`, `AGPL-*` etc. for pattern matching (case-insensitive)
- **Unknown license handling**: Configure how licenses not in either list are treated:
  - `warn` (default): Report as warning but don't fail
  - `deny`: Treat unknown licenses as violations
  - `allow`: Silently allow unknown licenses
- **Exit code**: Returns exit code 1 when policy violations are detected

### Abandoned Package Detection

Use the `--check-abandoned` option to identify packages that have not received a new release on PyPI within a configurable number of days. This surfaces unmaintained dependencies that may pose a long-term risk even when no CVE has been filed.

```bash
# Enable abandoned package detection (default threshold: 730 days / ~2 years)
uv-sbom --check-abandoned --format markdown

# Use a custom inactivity threshold (e.g., 365 days / 1 year)
uv-sbom --check-abandoned --abandoned-threshold-days 365

# Combined with vulnerability and license checks
uv-sbom --check-abandoned --check-license --severity-threshold high
```

**How it works:**
- Queries the PyPI package-level endpoint (`https://pypi.org/pypi/{name}/json`) for each package
- Compares the latest release date against today minus the configured threshold
- Packages exceeding the threshold appear in the **Abandoned Packages** section of the Markdown output
- If a package's PyPI metadata cannot be fetched, it is skipped without aborting the run
- Requires network access; adds one API call per package

**Output:**
- **Summary table row**: `| Abandoned packages | N | ⚠️ |` when count > 0, `✅` when count == 0
- **Abandoned Packages section**: Table with Package, Version, Last Release date, Days Inactive, and Type (Direct / Transitive)
- When `--check-abandoned` is not passed, the section is omitted entirely and the Summary row shows `_Abandoned package check skipped._`

**Config file equivalent:**
```yaml
check_abandoned: true
abandoned_threshold_days: 365  # optional, default: 730
```

**CI Integration example:**
```yaml
# GitHub Actions - Abandoned Package Check
- name: Abandoned Package Detection
  run: uv-sbom --check-abandoned --abandoned-threshold-days 730 --format markdown
```

> **Note:** Abandoned package data is currently Markdown-only. CycloneDX JSON output is not affected.

For a demo with guaranteed output, run:

```bash
uv-sbom -p examples/abandoned-packages-project --check-abandoned -f markdown
```

See [`examples/abandoned-packages-project/README.md`](examples/abandoned-packages-project/README.md) for a full walkthrough.

### Non-PyPI Source Detection

Use the `--check-non-pypi` option to identify packages installed from sources other than the official PyPI registry (git repositories, direct URLs, private registries). This helps detect potential supply chain risks unique to uv projects, since uv.lock explicitly records the source type for every package.

```bash
# Enable non-PyPI source detection
uv-sbom --check-non-pypi --format markdown
```

**How it works:**
- Reads the source classification directly from `uv.lock` (no network access, no PyPI API calls)
- Flags packages sourced from a **Private Registry**, **Git** repository, or **Direct URL**
- Local filesystem paths (`path = "..."`) and workspace members are not flagged — these are expected in uv workspace layouts and are not considered external supply chain risk

**Output:**
- **Non-PyPI Package Sources section**: Appears in the Markdown output listing the total count (direct vs. transitive) followed by a table of Package, Version, Source Type, and Source
- When `--check-non-pypi` is not passed, or no packages match, the section is omitted entirely

**Example output:**
```markdown
## ⚠️ Non-PyPI Package Sources

3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive).

| Package | Version | Source Type | Source |
|---------|---------|-------------|--------|
| acme-analytics-sdk | 1.4.0 | Private Registry | https://pypi.acme-corp.example/simple |
| edge-config | 2.1.0 | Direct URL | https://downloads.acme-corp.example/edge-config-2.1.0-py3-none-any.whl |
| telemetry-agent | 0.9.2 | Git | https://github.com/acme-corp/telemetry-agent?rev=9f2c1ab |

> Packages from non-PyPI sources may not be subject to PyPI's security policies. Review each package's origin before production deployment.
```

**Config file equivalent:**
```yaml
check_non_pypi: true
```

> **Note:** Non-PyPI source detection requires no network access — all data is read directly from `uv.lock`.

For a demo with guaranteed output, run:

```bash
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --no-check-cve -f markdown
```

See [`examples/non-pypi-sources-project/README.md`](examples/non-pypi-sources-project/README.md) for a full walkthrough.

### Python Version Compatibility Check

Use the `--target-python` option to check whether any dependency declares a `Requires-Python` constraint (via PyPI metadata) that is incompatible with a target Python version. This helps detect dependencies that would break if you upgraded (or downgraded) your project's Python version.

```bash
# Check compatibility with Python 3.8
uv-sbom --target-python 3.8 --format markdown

# Combine with other checks
uv-sbom --target-python 3.8 --check-license --severity-threshold high
```

**How it works:**
- Queries the PyPI version-level endpoint (`https://pypi.org/pypi/{name}/{version}/json`) for each locked package version
- Compares the package's declared `Requires-Python` constraint (PEP 440) against the target version
- Packages with no declared constraint, or an unparseable constraint, are treated as compatible
- If a package's PyPI metadata cannot be fetched, it is skipped without aborting the run
- Requires network access; adds one API call per package

**Output:**
- **Python Compatibility Issues section**: Appears in the Markdown output when any incompatible package is found, listing the total count (direct vs. transitive) followed by a table of Package, Version, Requires-Python, and Type
- **Python Compatibility section (all clear)**: Appears instead when every package is compatible with the target version
- When `--target-python` is not passed, no compatibility section is rendered

**Example output:**
```markdown
## ⚠️ Python 3.8 Compatibility Issues

11 package(s) incompatible with the target Python version (0 direct, 11 transitive).

| Package | Version | Requires-Python | Type |
|---------|---------|-----------------|------|
| coverage | 7.14.3 | >=3.10 | Transitive dependencies |
| iniconfig | 2.3.0 | >=3.10 | Transitive dependencies |
| librt | 0.11.0 | >=3.9 | Transitive dependencies |
| markupsafe | 3.0.3 | >=3.9 | Transitive dependencies |
| mypy | 2.1.0 | >=3.10 | Transitive dependencies |
| pathspec | 1.1.1 | >=3.9 | Transitive dependencies |
| pluggy | 1.6.0 | >=3.9 | Transitive dependencies |
| pygments | 2.20.0 | >=3.9 | Transitive dependencies |
| pytest | 9.1.1 | >=3.10 | Transitive dependencies |
| pytest-cov | 7.1.0 | >=3.9 | Transitive dependencies |
| typing-extensions | 4.15.0 | >=3.9 | Transitive dependencies |
```

Produced by running against [`examples/sample-project`](examples/sample-project):

```bash
uv-sbom -p examples/sample-project --target-python 3.8 --no-check-cve -f markdown
```

**Config file equivalent:**
```yaml
target_python: "3.8"
```

### Exploitability Prioritization (`--check-exploitability`)

Use the `--check-exploitability` option to enrich CVE results with real-world exploitation data from two authoritative sources:

- **EPSS** (Exploit Prediction Scoring System) from [FIRST.org](https://www.first.org/epss/) — a percentile ranking indicating the likelihood that a CVE will be exploited in the wild within the next 30 days
- **CISA KEV** (Known Exploited Vulnerabilities) catalog from [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — a curated list of CVEs with confirmed active exploitation

```bash
# Enrich vulnerability results with EPSS and KEV data
uv-sbom --check-exploitability --format markdown

# Combine with other checks
uv-sbom --check-exploitability --severity-threshold high --check-license
```

**How it works:**
- Fetches EPSS scores and percentiles from the FIRST.org EPSS API (`https://api.first.org/data/v1/epss`)
- Downloads the CISA KEV JSON feed to check whether each CVE has confirmed active exploitation
- Results are displayed as two additional columns in the vulnerability table and resolution guide
- If exploitability data is not available for any CVE, the columns are omitted entirely

**Output:**
- **Exploited (KEV) column**: Shows "Yes" for CVEs in the CISA KEV catalog, "No" otherwise
- **EPSS column**: Shows the EPSS percentile as an ordinal string (e.g., "97th percentile")
- These columns appear only when at least one CVE has exploitability data

**Example output:**

Produced by running against [`examples/suggest-fix-project`](examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --check-exploitability -f markdown
```

```markdown
## Vulnerability Report

| Package | Current Version | Fixed Version | CVSS | Severity | Vulnerability ID | Exploited (KEV) | EPSS |
|---------|-----------------|---------------|------|----------|------------------|-----------------|------|
| urllib3 | 2.0.4 | 2.6.3 | 7.5 | 🟠 HIGH | GHSA-38jv-5279-wg99 | No | 87th percentile |
| certifi | 2023.7.22 | 2024.7.4 | N/A | 🟢 LOW | GHSA-248v-346w-9cwc | No | 63rd percentile |
| h11 | 0.14.0 | 0.16.0 | 9.1 | 🔴 CRITICAL | GHSA-vqfr-h8mv-ghfj | No | 46th percentile |
| urllib3 | 2.0.4 | 2.0.7 | 4.2 | 🟡 MEDIUM | GHSA-g4mx-q9vg-27p4 | No | 43rd percentile |
| anyio | 4.0.0 | 4.14.2 | N/A | 🔴 CRITICAL | GHSA-82r6-8w77-94w6 | No | 19th percentile |
```

_(32 vulnerabilities total — excerpt sorted by EPSS percentile. EPSS values are live data and may change over time.)_

**Config file equivalent:**
```yaml
check_exploitability: true
```

> **Note:** `--check-exploitability` requires CVE checking to be enabled and conflicts with `--no-check-cve`. It adds two network requests (FIRST.org EPSS API and CISA KEV catalog feed) per SBOM generation.

### Dependency Explanation (`--explain`)

Use the `--explain <PACKAGE_NAME>` option to trace how a package ended up in your dependency tree. It answers "why is this package here?" by printing every path from a direct dependency down to the target package.

```bash
# Trace why idna is included
uv-sbom --explain idna --format markdown

# Combine with other options
uv-sbom --explain idna --no-check-cve --format markdown
```

**How it works:**
- Reuses the dependency graph already built for the Markdown report — no network access and no additional traversal
- Reports the package as a **direct dependency** when it appears in `[project.dependencies]`, and lists every transitive path otherwise (a package can be both)
- Paths read left to right, from the direct dependency to the target, using the same backtick-and-arrow notation as the Dependency Chains subsection
- An unknown or invalid package name is reported as "not found"; it never aborts SBOM generation
- The graph is built only from `[project.dependencies]`. Packages reachable only through `[dependency-groups]` (dev, test, lint, …) are reported as not found, even though they still appear in the component inventory and license tables

**Output:**
- **Dependency Explanation section**: a single `## Dependency Explanation` section in the Markdown output, rendered in one of three states — transitive paths, direct dependency, or not found
- When `--explain` is not passed, the section is omitted entirely

**Example output (transitive package reached by several paths):**
```markdown
## Dependency Explanation

**idna** is included via 3 path(s):

- `httpx` → `idna`
- `requests` → `idna`
- `httpx` → `httpcore` → `anyio` → `idna`
```

Produced by running against [`examples/suggest-fix-project`](examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --explain idna --no-check-cve -f markdown
```

**Example output (direct dependency):**
```markdown
## Dependency Explanation

**requests** is a direct dependency of this project.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain requests --no-check-cve -f markdown
```

**Example output (package not found):**
```markdown
## Dependency Explanation

Package **definitely-not-a-real-package** was not found in this project's dependencies.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain definitely-not-a-real-package --no-check-cve -f markdown
```

> **Note:** These examples use `examples/suggest-fix-project` rather than `examples/sample-project` (used elsewhere in this README) because it is the shipped example that actually contains a diamond dependency — `idna` is required by both `httpx` and `requests`.

**Config file equivalent:**

None. `--explain` is intentionally CLI-only: it is a one-off diagnostic query about a single package, not a persistent policy setting like `check_non_pypi` or `target_python`. It has no `uv-sbom.config.yml` key and does not appear in the Config File Schema Reference table.

**Flag interactions:**
- **`--workspace` is rejected.** The combination is a hard error at argument-parsing time:
  ```
  error: the argument '--explain <PACKAGE_NAME>' cannot be used with '--workspace'
  ```
- **`--format json` silently produces nothing.** CycloneDX JSON output never includes explain data, and unlike `--check-license` and `--verify-links`, no "no effect" warning is printed for this combination. Since `json` is the default format, always pass `--format markdown` (or `-f markdown`) with `--explain`.

### Dependency Tree Visualization (`--show-dependency-tree`)

Use `--show-dependency-tree` to render your project's dependency graph as an ASCII tree in the Markdown output. Use `--dependency-tree-depth <DEPTH>` (default: 3) to control how many levels below each direct dependency are expanded.

```bash
# Show the full dependency tree
uv-sbom --show-dependency-tree --format markdown

# Limit the tree to 2 levels below each root
uv-sbom --show-dependency-tree --dependency-tree-depth 2 --format markdown
```

**How it works:**
- Reuses the dependency graph already built for the Markdown report — no network access and no additional traversal
- One root per direct dependency, in the same order as the Direct Dependencies list; children follow the lock file's own dependency order
- Diamond dependencies (a package reachable through more than one path) are shown once under each parent, not deduplicated — the tree mirrors graph shape, not a flattened package list
- `--dependency-tree-depth` counts levels *below* each root: `0` shows roots only, `1` shows roots plus their immediate children, and so on
- When a branch has children that were not expanded because the depth limit was reached, a `... (truncated)` marker is shown in their place, followed by a note naming the depth that was applied

**Output:**
- **Dependency Tree section**: a single `## Dependency Tree` section in the Markdown output, containing only package name and version — license, description, and hash data are not repeated here since they already appear in the Component Inventory
- When `--show-dependency-tree` is not passed, the section is omitted entirely

**Example output (full tree, no truncation):**

Produced by running against [`examples/suggest-fix-project`](examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   ├── idna (3.4)
│   │   │   └── sniffio (1.3.0)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```
````

**Example output (truncated at depth 2):**

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --dependency-tree-depth 2 --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   └── ... (truncated)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```

_Tree truncated at depth 2. Use `--dependency-tree-depth <DEPTH>` to show more levels._
````

> **Note:** These examples use `examples/suggest-fix-project` rather than `examples/sample-project` (used elsewhere in this README) because it is the shipped example with a chain deep enough (`httpx` → `httpcore` → `anyio` → `idna`/`sniffio`) to actually demonstrate truncation at a reduced depth.

**Config file equivalent:**

None. `--show-dependency-tree` is intentionally CLI-only: it is a one-off visualization request, not a persistent policy setting like `check_non_pypi` or `target_python`. It has no `uv-sbom.config.yml` key and does not appear in the Config File Schema Reference table.

**Flag interactions:**
- **`--format json` silently produces nothing.** CycloneDX JSON output never includes the dependency tree, and no "no effect" warning is printed for this combination. Since `json` is the default format, always pass `--format markdown` (or `-f markdown`) with `--show-dependency-tree`.

### Vulnerability Threshold Options

You can control which vulnerabilities trigger a non-zero exit code using threshold options:

```bash
# Check for any vulnerabilities (exits with 1 if found)
uv-sbom --format markdown

# Check for High or Critical severity only
uv-sbom --format markdown --severity-threshold high

# Check for Critical severity only
uv-sbom --format markdown --severity-threshold critical

# Check for CVSS >= 7.0 only
uv-sbom --format markdown --cvss-threshold 7.0

# Check for CVSS >= 9.0 (Critical) only
uv-sbom --format markdown --cvss-threshold 9.0
```

**Threshold Options:**
- `--severity-threshold <LEVEL>`: Filter by severity level (low, medium, high, critical)
- `--cvss-threshold <SCORE>`: Filter by CVSS score (0.0-10.0)

**Notes:**
- Only one threshold option can be used at a time
- Cannot be used with `--no-check-cve`
- Vulnerabilities below the threshold are still shown in the report but don't trigger exit code 1
- When using `--cvss-threshold`, vulnerabilities without CVSS scores (N/A) are excluded from threshold evaluation

### PyPI Link Verification

Use the `--verify-links` option to validate that packages exist on PyPI before generating hyperlinks. Packages that don't exist on PyPI will be rendered as plain text:

```bash
# Generate Markdown with verified PyPI links
uv-sbom --format markdown --verify-links

# Combine with other options
uv-sbom --format markdown --verify-links --output SBOM.md
```

**Behavior:**
- Without `--verify-links`: All package names get PyPI hyperlinks (default, fast)
- With `--verify-links`: Only verified packages get hyperlinks; unverified packages render as plain text
- Network errors gracefully fall back to plain text (no crash)
- Requests are executed in parallel (max 10 concurrent) for performance

### Dependency Diff

Use the `--diff` option to compare the current `uv.lock` against a previous version. This is useful for reviewing what changed between branches, tags, or arbitrary lockfile snapshots before merging.

```bash
# Compare against a git branch or tag
uv-sbom --diff main
uv-sbom --diff v1.2.0
uv-sbom --diff abc1234    # abbreviated commit SHA

# Compare against a file path (absolute or relative to CWD)
uv-sbom --diff /path/to/old/uv.lock

# Output as Markdown report
uv-sbom --diff main --format markdown --output diff.md

# Output as JSON
uv-sbom --diff main --format json
```

**Auto-detection:** If the argument resolves to an existing file on disk it is treated as a file path; otherwise it is treated as a git ref. Relative paths are resolved against the process working directory (not `--path`).

**Git ref validation:** Only `[a-zA-Z0-9._/-]` characters are allowed in git refs. Refs starting with `-` are also rejected. This prevents command injection.

**Mutual exclusion:** `--diff` cannot be combined with `--workspace` or `--init`.

#### CVE Delta

By default, `--diff` also runs vulnerability checks on both the base and current lock files and appends a **CVE Delta** section to the report showing which vulnerabilities were introduced or resolved:

- **New vulnerabilities** — CVEs that affect packages in the current lock but were not present in the base.
- **Resolved vulnerabilities** — CVEs that affected packages in the base lock but no longer apply.

```bash
# Diff with CVE delta (default — CVE checking is on)
uv-sbom --diff main

# Disable CVE checking in diff mode
uv-sbom --diff main --no-check-cve
```

JSON output includes a top-level `cve_delta` key with `new` and `resolved` arrays. The key is omitted entirely when `--no-check-cve` is passed.

**Severity and CVSS filtering:** `--severity-threshold` and `--cvss-threshold` apply to the CVE delta. Only entries at or above the threshold appear in the tables. The process exits with code `1` when new CVEs above the configured threshold are introduced.

```bash
# Show only HIGH and above CVE delta entries
uv-sbom --diff main --severity-threshold high

# Show only CVE delta entries with CVSS ≥ 7.0
uv-sbom --diff main --cvss-threshold 7.0
```

**CI example:**
```bash
# Fail the build if new dependencies introduced by this PR have known HIGH+ CVEs
uv-sbom --diff origin/main --format markdown --output diff.md --severity-threshold high
```

### Incident Response (`--incident`)

When a new advisory is announced, `--incident <ADVISORY_ID>` (or a quoted version range for an advisory not yet in OSV) answers three questions for your project in one command: **am I affected, is the patch out, and what do I run?**

```bash
# Look up a GHSA, PYSEC, CVE, OSV, or MAL ID
uv-sbom --incident GHSA-v845-jxx5-vc9f

# A CVE ID is resolved to its GHSA/PYSEC record automatically
uv-sbom --incident CVE-2023-43804 -p path/to/project

# JSON for automation, or write the report to a file
uv-sbom --incident GHSA-v845-jxx5-vc9f --format json
uv-sbom --incident GHSA-v845-jxx5-vc9f --output incident.md

# Advisory not in OSV yet: pass the affected range yourself (quote it!)
uv-sbom --incident "urllib3<2.0.6"
```

**Accepted IDs:** IDs starting with `GHSA-`, `PYSEC-`, `CVE-`, `OSV-`, or `MAL-`. The prefix is case-insensitive. Any other value is read as a manual range (see below), and a value that is neither is rejected with exit code `2`. When the record you ask for lists no PyPI package (typical for a `CVE-` ID), uv-sbom follows its `GHSA-` and then `PYSEC-` aliases and notes which ID the report was resolved from.

**Output:** the report is **Markdown by default** (unlike SBOM generation, which defaults to JSON). It has three sections:

1. **Impact** — each package the advisory names, its locked version, the verdict, and whether it is a direct or transitive dependency (with dependency paths).
2. **Patch status** — the fixed version and whether it is released on PyPI.
3. **Next action** — a copy-paste `uv lock --upgrade-package <name>==<fixed>` + `uv sync` command. It is verified with a dry-run resolution first, and your `uv.lock` is not modified. If the upgrade cannot be resolved, or no fix is released, you get guidance instead. When the blocked package is itself a direct dependency, the guidance tells you to relax its version requirement in `pyproject.toml` to allow the fixed version.

Example against `examples/suggest-fix-project` (exit code `1`):

````markdown
## Incident Report: GHSA-v845-jxx5-vc9f

- **Aliases**: CVE-2023-43804, PYSEC-2023-192
- **Severity**: MEDIUM
- **Summary**: `Cookie` HTTP header isn't stripped on cross-origin redirects
- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

**Workspaces (`--workspace`):** in a uv workspace root, `--incident <ID> --workspace` checks every member in one run and prints **one combined report**: the advisory heading, a `1. Impact` subsection per member with that member's verdict and dependency paths, shared `2. Patch status` and `3. Next action` sections (the upgrade command is the same for every member, because the workspace shares one `uv.lock`), and a final "N of M members affected" line. The advisory and its PyPI release status are fetched once per run, not once per member, and the dry-run resolution runs against the workspace root. The exit code is the most actionable member verdict (using the same table as below). No per-member `sbom.*` file is written, and the report always goes to stdout (`--workspace` cannot be combined with `--output`).

```bash
uv-sbom --incident GHSA-82w8-qh3p-5jfq --workspace -p examples/workspace
```

Output against `examples/workspace`, where only the `api` member reaches `starlette` (through `fastapi`) (exit code `1`):

````markdown
## Incident Report: GHSA-82w8-qh3p-5jfq

- **Aliases**: CVE-2026-54283, PYSEC-2026-249
- **Severity**: HIGH
- **Summary**: Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS
- **Overall verdict**: Affected — fix released

### 1. Impact

#### Member: api

- **Verdict**: Affected — fix released
- **starlette** 1.0.0 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `fastapi → starlette`

#### Member: worker

- **Verdict**: Not affected

None of the affected packages (starlette) are reachable from this member.

### 2. Patch status

- **starlette**: fixed in 1.3.1 — released

### 3. Next action

**starlette** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package starlette==1.3.1
uv sync
```

**1 of 2 members affected**: api
````

**Workspace root dependency groups in incident mode:** like `--workspace` (see **Workspace root dependency groups** under [uv Workspace Support](#uv-workspace-support)), `--incident --workspace` prints a warning on stderr naming each virtual-root `[dependency-groups]` group that is not excluded, because no member scope follows those groups and packages reachable only through them are not checked against the advisory. The warning is printed after the progress lines and before the report, only when the run succeeds. The report on stdout (Markdown or JSON) and the exit code are unchanged, so `--format json | jq` keeps working. Add the root groups to `--exclude-groups` (or use `--production-only`) to silence it. The stderr of the command above ends with:

```
⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

**Manual range (advisory not yet in OSV):** in the first hours after a disclosure, the advisory may not be in OSV yet, so an ID has nothing to look up. Security announcements usually state the affected range in plain text ("versions before 2.0.6 are affected"), so you can pass that range instead of an ID: a package name immediately followed by one or more comma-separated specifiers.

```bash
uv-sbom --incident "foo<2.3.2"          # affected below 2.3.2; 2.3.2 is the fix
uv-sbom --incident "foo>=2.0,<2.3.2"    # affected from 2.0 up to (not including) 2.3.2
uv-sbom --incident "foo<=2.3.1"         # affected up to 2.3.1; no fix known yet
```

| Specifier | Meaning |
|-----------|---------|
| `>=X` | First affected version (optional; without it, every version below the upper bound is affected) |
| `<X` | Fixed version. Patch status and the verified upgrade command work exactly as with an advisory ID |
| `<=X` | Last affected version. No fix is known, so the verdict is "no fix available" (exit `4`) |

- **Quote the argument.** In the shell, `<` is an input redirection: `uv-sbom --incident foo<2.3.2` would try to read a file named `2.3.2`.
- Only `>=`, `<`, and `<=` are accepted, with at most one lower bound and one upper bound (not `<` and `<=` together). Other operators (`==`, `!=`, `~=`, `>`, `===`), a bare package name, and a range that contains no versions (e.g. `"foo>=2.3,<2.0"`) are rejected with exit code `2`, not guessed.
- With `>=` alone, the verdict is also "no fix available" (exit `4`).
- One range per run. For fixes on several release lines, run the command once per range.
- No OSV request is made. The report header shows the range and states that it was supplied by you and not verified against a vulnerability database. In JSON output, `source` is `"manual"` (it is `"osv"` for an advisory ID), and `advisory_id` holds the range.
- Works with `--workspace`, `--format json`, and `--lang ja`, the same as an advisory ID, with the same exit codes.

Example against `examples/suggest-fix-project` (exit code `1`):

````markdown
## Incident Report (manual range): `urllib3<2.0.6`

⚠️ This affected range was supplied by you. It is not taken from a vulnerability database and has not been verified.

- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

**Exit codes:**

| Verdict | Exit Code |
|---------|-----------|
| Not affected (including an advisory that names no PyPI package) | 0 |
| Affected, fix released | 1 |
| Affected, fix not yet released, or no fix available | 4 |
| Unknown advisory ID, network error, or other application error | 3 |
| Malformed advisory ID or range, or conflicting flags | 2 |

**Scope options honored:** `--path`, `--exclude`, `--exclude-groups`, `--production-only`, `--output` (not with `--workspace`), `--format`, `--lang`, and `--config`. The config file's `exclude_packages` and `exclude_groups` also apply.

**Ignored config keys:** the config file's `format` is never used in incident mode; only `--format` changes the output. The vulnerability, license, maintenance, and compatibility check keys (`check_cve`, `severity_threshold`, `cvss_threshold`, `ignore_cves`, `check_license`, `license_policy`, `check_abandoned`, `check_non_pypi`, `check_exploitability`, `target_python`, `suggest_fix`, `baseline_file`) are ignored too.

**Mutual exclusion:** `--incident` cannot be combined with `--diff`, `--init`, `--dry-run`, `--explain`, `--show-dependency-tree`, `--no-check-cve`, `--baseline`, `--update-baseline`, `--suggest-fix`, `--check-license`, `--check-abandoned`, `--check-non-pypi`, `--check-exploitability`, `--target-python`, `--severity-threshold`, `--cvss-threshold`, `--ignore-cve`, or `--verify-links`. It can be combined with `--workspace` (see above).

**Config file key:** None. `--incident` is intentionally CLI-only: it is a one-off query about a single advisory (or range), not a persistent policy setting.

### Vulnerability Baseline

Use `--baseline` to suppress previously-accepted vulnerability findings. A baseline file records `(package, version, vulnerability_id)` tuples. Only exact matches are suppressed — bumping a package version makes its previously-baselined findings count as new.

```bash
# First run: generate a baseline file from the current findings
uv-sbom --baseline .uv-sbom-baseline.json --update-baseline

# Subsequent runs: suppress known findings; new ones still trigger exit code 1
uv-sbom --baseline .uv-sbom-baseline.json
```

The baseline file is a JSON document with a `version` key and an `entries` array:

```json
{
  "version": 1,
  "entries": [
    {
      "package": "requests",
      "version": "2.25.0",
      "id": "GHSA-9wx4-h78v-vm56"
    }
  ]
}
```

**`--update-baseline`** rewrites the baseline file with all current (unfiltered) findings. Use it when you accept a new batch of known CVEs. Requires `--baseline`.

When findings are suppressed, the Markdown vulnerability section includes a footnote:

> _Note: 3 previously-baselined finding(s) suppressed._

**Configuration file:** Set `baseline_file` in `uv-sbom.config.yml` instead of passing `--baseline` on every invocation:

```yaml
baseline_file: .uv-sbom-baseline.json
```

**Mutual exclusion:** `--baseline` cannot be combined with `--no-check-cve` (baselines require vulnerability checking).

**CI workflow:**
```bash
# Check for new vulnerabilities while suppressing accepted ones
uv-sbom --baseline .uv-sbom-baseline.json --severity-threshold high -f markdown -o report.md

# After review, accept all current findings into the baseline
uv-sbom --baseline .uv-sbom-baseline.json --update-baseline
```

### CI Integration

Use vulnerability thresholds for CI/CD pipeline integration:

```yaml
# GitHub Actions example
- name: Generate SBOM
  run: uv-sbom --format markdown --output sbom.md

- name: Security Check (High and Critical only)
  run: uv-sbom --format markdown --severity-threshold high

- name: Security Check (CVSS >= 7.0)
  run: uv-sbom --format markdown --cvss-threshold 7.0
```

```yaml
# GitHub Actions - License Compliance Check
- name: License Compliance Check
  run: uv-sbom --check-license --format markdown

- name: Combined Security and License Check
  run: uv-sbom --check-license --severity-threshold high
```

```yaml
# GitHub Actions - Abandoned Package Check
- name: Abandoned Package Detection
  run: uv-sbom --check-abandoned --format markdown
```

```yaml
# GitLab CI example
security_scan:
  script:
    - uv-sbom --format markdown --severity-threshold high
  allow_failure: false
```

**Important Notes:**
- Vulnerability checking is **only available for Markdown format**
- Requires internet connection to query OSV API
- Not available in `--dry-run` mode (skips network operations)
- Use `--exclude` to prevent internal packages from being sent to OSV API

**Example Output:**

When vulnerabilities are found, a section like this is added to the Markdown output:

```markdown
## Vulnerability Report

**⚠️ Security Issues Detected**

The following packages have known security vulnerabilities:

| Package | Current Version | Fixed Version | CVSS | Severity | CVE ID |
|---------|----------------|---------------|------|----------|--------|
| urllib3 | 2.0.0 | 2.0.7 | 9.8 | 🔴 CRITICAL | CVE-2023-45803 |
| requests | 2.28.0 | 2.31.0 | 7.5 | 🟠 HIGH | CVE-2023-32681 |

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
```

> **Note:** Vulnerability IDs (CVE, GHSA, PYSEC, RUSTSEC, etc.) in the vulnerability report are always rendered as hyperlinks, regardless of `--verify-links`. These IDs are sourced from the OSV database and link to authoritative vulnerability databases (NVD, GitHub Advisories, OSV.dev), so link verification is unnecessary.

### Vulnerability Resolution Guide

When vulnerabilities are detected in transitive dependencies, uv-sbom automatically generates a **Vulnerability Resolution Guide**. This section shows which direct dependency introduces each vulnerable transitive package, so you know exactly what to upgrade.

#### Markdown output example

```markdown
## Vulnerability Resolution Guide

The following transitive dependencies have known vulnerabilities. The table shows which direct dependency introduces each vulnerable package.

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Vulnerability ID |
|--------------------|---------|---------------|----------|---------------------------|-----------------|
| urllib3 | 1.26.15 | >= 2.0.7 | 🟠 HIGH | requests (2.31.0) | [CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX) |
| h11 | 0.14.0 | >= 0.14.4 | 🟠 HIGH | httpx (0.24.0) | [CVE-2024-ZZZZZ](https://nvd.nist.gov/vuln/detail/CVE-2024-ZZZZZ) |

### Dependency Chains

**`h11 0.14.0`** — CVE-2024-ZZZZZ (HIGH)
- `httpcore` → `httpx` → **`h11 0.14.0`** ⚠️
```

> **Note:** The `### Dependency Chains` subsection is only rendered when at least one vulnerable package is reachable via a multi-hop chain (chain length > 2). It is omitted entirely when all vulnerable packages are introduced directly by a first-level dependency.

#### CycloneDX JSON output

In CycloneDX format, the introducing dependency is included as a `properties` entry:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "properties": [
        {
          "name": "uv-sbom:introduced-by",
          "value": "requests@2.31.0"
        }
      ]
    }
  ]
}
```

> **Note:** The resolution guide only appears for **transitive** dependency vulnerabilities. Direct dependency vulnerabilities are shown in the standard vulnerability table, as users can upgrade them directly.

### Upgrade Advisor (`--suggest-fix`)

Use `--suggest-fix` to automatically suggest which direct dependency version to upgrade to resolve each transitive vulnerability.

**Requires**:
- `uv` CLI installed
- `pyproject.toml` in the project directory

**Example**:
```bash
uv-sbom generate --suggest-fix
```

**Output**: Adds a "Recommended Action" column to the Vulnerability Resolution Guide showing:
- `⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)` — when an upgrade fixes the vulnerability
- `⚠️ Cannot resolve: latest httpx still pins idna < 3.7` — when no upgrade helps
- `❓ Could not analyze: <error>` — when simulation failed

**Try it with the included example**:

```bash
# This example has transitive CVEs designed to show both Upgradable and Unresolvable outcomes
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

See [`examples/suggest-fix-project/README.md`](examples/suggest-fix-project/README.md) for a full walkthrough.

**License Compliance Check output example:**

```markdown
## License Compliance Check

Policy: 3 allowed patterns, 1 denied pattern | Unknown: warn

### Violations (2 found)

| Package | Version | License | Reason |
|---------|---------|---------|--------|
| some-gpl-lib | 1.0.0 | GPL-3.0 | Denied by policy |
| mystery-pkg | 2.1.0 | Unknown | Not in allow list |
```

When no vulnerabilities are found:

```markdown
## Vulnerability Report

**✅ No Known Vulnerabilities**

No security vulnerabilities were found in the scanned packages.

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
```

### uv Workspace Support

[uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/) let you manage multiple Python
packages in a single repository with a shared `uv.lock` file. `uv-sbom --workspace` generates a separate
SBOM for each member package, reflecting only the dependencies reachable from that member.

**When to use:**
- Your repository contains multiple Python packages (e.g., `api/`, `worker/`)
- You need per-member SBOMs for independent security scanning or compliance reporting

**Usage:**

```bash
# Generate one SBOM per workspace member (CycloneDX JSON, default)
uv-sbom --workspace --path /path/to/workspace
```

**Expected output:**

```
Workspace mode: 2 members found

  Processing: api
  ...
  Processing: worker
  ...

📦 Workspace SBOM Summary
────────────────────────────────────────────────────────────
Member               Output File
────────────────────────────────────────────────────────────
api                  /path/to/workspace/packages/api/sbom.json
worker               /path/to/workspace/packages/worker/sbom.json
────────────────────────────────────────────────────────────

📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

Each member gets its own `sbom.json` containing only the packages reachable from that member.
Transitive dependencies are included, but packages belonging to other members are excluded.

**Aggregate summary across members:** After the per-member table, `--workspace` also prints an
aggregate summary showing monorepo-wide health without opening every member's SBOM file — total
CVE count, which members have license policy violations, and which members have abandoned /
non-PyPI / Python-incompatible packages flagged. A line only appears for a check that was actually
enabled for the run (e.g. `--check-license`); a check that wasn't run never prints a line, even an
empty one.

**Workspace root dependency groups:** A virtual workspace root (a root `pyproject.toml` with no
`[project]`) can declare its own `[dependency-groups]`, for example a `lint` group for repository-wide
tooling. No member SBOM follows those groups, so `--workspace` prints a warning on stderr naming each
root group that is not excluded, as in the last lines of the output above (`examples/workspace` declares
`lint = ["ruff"]` at its root). Packages a member reaches through its own dependencies still appear in
that member's SBOM. To silence the warning, add the root groups to `--exclude-groups` (or use
`--production-only`). stdout and the member SBOM files are unchanged. A root with a `[project]` is a
member itself, and its groups are covered by its own SBOM.

**With other options:**

```bash
# Markdown output for all members
uv-sbom --workspace --path examples/workspace --format markdown

# With license compliance check
uv-sbom --workspace --path examples/workspace --check-license
```

```
📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
Members with license policy violations: none
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

> **Note:** `--workspace` and `--output` are mutually exclusive. In workspace mode, each member's SBOM is
> automatically written to `sbom.json` (or `sbom.md` for Markdown) inside the member's own directory.

See [`examples/workspace/`](examples/workspace/) for a runnable demo with two member packages (`api` and `worker`).

### Validating configuration with dry-run

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

## Security

### Exclude Pattern Input Validation

The `-e`/`--exclude` option implements the following security measures to protect against malicious input:

#### Character Restrictions

Only the following characters are allowed in patterns:
- **Alphanumeric characters**: a-z, A-Z, 0-9, Unicode letters/numbers
- **Hyphens** (`-`), **underscores** (`_`), **dots** (`.`): Common in package names
- **Square brackets** (`[`, `]`): For package extras (e.g., `requests[security]`)
- **Asterisks** (`*`): For wildcard matching

Control characters, shell metacharacters, and path separators are blocked to prevent:
- Terminal escape sequence injection
- Log injection attacks
- Command injection (defense in depth)

#### Pattern Limits

- **Maximum patterns**: 64 patterns can be specified per invocation
- **Maximum length**: 255 characters per pattern
- **Minimum content**: Patterns must contain at least one non-wildcard character

These limits prevent denial-of-service attacks via:
- Excessive memory consumption
- CPU exhaustion from complex pattern matching

#### Examples

**Valid patterns**:
```bash
uv-sbom -e 'pytest'           # Exact match
uv-sbom -e 'test-*'           # Prefix wildcard
uv-sbom -e '*-dev'            # Suffix wildcard
uv-sbom -e 'package[extra]'   # Package with extras
```

**Invalid patterns** (rejected with error):
```bash
uv-sbom -e ''                 # Empty pattern
uv-sbom -e '***'              # Only wildcards
uv-sbom -e 'pkg;rm -rf /'     # Contains shell metacharacter
uv-sbom -e "$(cat /etc/passwd)" # Shell command substitution blocked
```

For more detailed security information, including threat model and attack vectors, see [SECURITY.md](SECURITY.md).

## Command-line options

```
Options:
  -f, --format <FORMAT>              Output format: json or markdown [default: json; markdown in --incident mode]
  -p, --path <PATH>                  Path to the project directory [default: current directory]
  -o, --output <OUTPUT>              Output file path (if not specified, outputs to stdout)
  -e, --exclude <PATTERN>            Exclude packages matching patterns (supports wildcards: *)
  -c, --config <PATH>               Path to config file (auto-discovers uv-sbom.config.yml if not specified)
  -i, --ignore-cve <CVE_ID>         CVE IDs to ignore (can be specified multiple times)
      --lang <LANG>                  Output language for human-readable formats: en or ja [default: en]
      --init                         Generate a uv-sbom.config.yml template file
      --dry-run                      Validate configuration without network communication or output generation
      --verify-links                 Verify PyPI links exist before generating hyperlinks (Markdown format only)
      --no-check-cve                 Disable CVE vulnerability checking (enabled by default)
      --severity-threshold <LEVEL>   Severity threshold for vulnerability check (low/medium/high/critical)
                                     Cannot be used with --no-check-cve
      --cvss-threshold <SCORE>       CVSS threshold for vulnerability check (0.0-10.0)
                                     Cannot be used with --no-check-cve
      --suggest-fix                  Suggest direct dependency upgrade versions to resolve transitive vulnerabilities
                                     Requires uv CLI installed and pyproject.toml in project directory
      --workspace                    Generate one SBOM per workspace member
                                     Cannot be used with --output
      --diff <REF_OR_PATH>           Compare current uv.lock against a base (git ref, tag, commit SHA, or path to a uv.lock file)
      --check-license                Check license compliance against policy
      --check-abandoned              Check for abandoned/unmaintained packages (no upstream release within threshold days)
      --abandoned-threshold-days <DAYS>  Inactivity threshold in days for abandoned-package detection (default: 730)
      --check-non-pypi               Check for packages sourced from non-PyPI origins (git, direct URL, private registries)
      --check-exploitability         Enrich CVE results with EPSS scores and CISA KEV status
                                     Cannot be used with --no-check-cve
      --license-allow <LIST>         Comma-separated list of allowed license patterns (overrides config)
      --license-deny <LIST>          Comma-separated list of denied license patterns (overrides config)
      --exclude-groups <GROUPS>      Exclude packages reachable only through the specified dependency groups (comma-separated)
                                     Example: --exclude-groups dev,test,lint. Cannot be used with --production-only
      --production-only              Exclude all non-default dependency groups (production-only mode)
                                     Cannot be used with --exclude-groups
      --target-python <VERSION>      Target Python version for compatibility checking (PEP 440 format, e.g. 3.8)
      --baseline <PATH>              Path to a vulnerability baseline file for suppressing previously-accepted findings
                                     Cannot be used with --no-check-cve
      --update-baseline              Update the baseline file with all current vulnerability findings after SBOM generation
                                     Requires --baseline
      --explain <PACKAGE_NAME>       Trace the dependency path(s) to the given package (Markdown format only)
                                     Cannot be used with --workspace
      --show-dependency-tree        Render the dependency graph as an ASCII tree (Markdown format only)
      --dependency-tree-depth <DEPTH>  Maximum depth for the dependency tree visualization (default: 3)
                                     Requires --show-dependency-tree
      --incident <ID_OR_RANGE>       Check whether one advisory (GHSA-/PYSEC-/CVE-/OSV-/MAL- ID) affects the project,
                                     whether the fix is released, and which command to run (Markdown by default)
                                     For an advisory not yet in OSV, pass a quoted range such as "foo>=2.0,<2.3.2"
                                     (operators >=, <, <= only)
                                     With --workspace, reports every member in one combined report
                                     Cannot be used with --diff or the check flags (see Incident Response)
  -h, --help                         Print help
  -V, --version                      Print version
```

## Exit Codes

uv-sbom returns the following exit codes:

| Exit Code | Description | Examples |
|-----------|-------------|----------|
| 0 | Success | SBOM generated successfully, no vulnerabilities above threshold, `--help` or `--version` displayed |
| 1 | Vulnerabilities or license violations detected | Vulnerabilities above threshold detected, license policy violations found |
| 2 | Invalid command-line arguments | Unknown option, invalid argument type, malformed `--incident` advisory ID or range |
| 3 | Application error | Missing uv.lock file, invalid project path, invalid exclude pattern, network error, file write error, unknown `--incident` advisory ID |
| 4 | Affected, no released fix (`--incident` only) | The project is affected by the advisory, but the fix is not yet released on PyPI or no fix exists |

### Exit Codes with Vulnerability and License Checking

When using CVE or license checking, the exit code behavior changes based on threshold settings:

| Scenario | Exit Code |
|----------|-----------|
| No vulnerabilities found | 0 |
| Vulnerabilities found (no threshold specified) | 1 |
| Vulnerabilities found, all below threshold | 0 |
| Vulnerabilities found, some above threshold | 1 |
| License policy violations detected | 1 |
| Combined: either check fails | 1 |
| Combined: both checks pass | 0 |

**Examples:**
```bash
# Returns 0 if no High/Critical vulnerabilities, even if Low/Medium exist
uv-sbom --format markdown --severity-threshold high

# Returns 0 if no vulnerabilities have CVSS >= 7.0
uv-sbom --format markdown --cvss-threshold 7.0
```

### Common Error Scenarios

**Exit code 3 - Application errors:**
```bash
# Missing uv.lock file
$ uv-sbom --path /path/without/uv-lock
❌ An error occurred:
uv.lock file not found: /path/without/uv-lock/uv.lock
# Exit code: 3

# Invalid exclude pattern (empty)
$ uv-sbom -e ""
❌ An error occurred:
Exclusion pattern cannot be empty
# Exit code: 3

# Invalid exclude pattern (invalid characters)
$ uv-sbom -e "pkg;name"
❌ An error occurred:
Exclusion pattern contains invalid character ';' in pattern 'pkg;name'
# Exit code: 3

# Nonexistent project path
$ uv-sbom --path /nonexistent
❌ An error occurred:
Invalid project path: /nonexistent
# Exit code: 3
```

**Exit code 2 - CLI argument errors:**
```bash
# Unknown option
$ uv-sbom --unknown-option
error: unexpected argument '--unknown-option' found
# Exit code: 2

# Invalid format value
$ uv-sbom --format invalid
error: invalid value 'invalid' for '--format <FORMAT>'
# Exit code: 2
```

### Usage in Scripts

```bash
#!/bin/bash

uv-sbom --format json --output sbom.json

case $? in
  0)
    echo "SBOM generated successfully"
    ;;
  1)
    echo "Vulnerabilities detected above threshold"
    exit 1
    ;;
  2)
    echo "Invalid command-line arguments"
    exit 2
    ;;
  3)
    echo "Application error occurred"
    exit 3
    ;;
esac
```

## Output Examples

### Markdown format

> **Note**: The Markdown format sample is based on the SBOM format from [ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0).

```markdown
## Summary

| Item | Count | Status |
|------|-------|--------|
| Direct dependencies | 2 | ✅ |
| Transitive dependencies | 3 | ✅ |
| ...vulnerability rows... | | |
| License violations | 0 | ✅ |

**Overall: No issues found** ✅

# Software Bill of Materials (SBOM)

## Component Inventory

A comprehensive list of all software components and libraries included in this project.

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |
| ...additional packages... |

## Direct Dependencies

Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |

## Transitive Dependencies

Secondary dependencies introduced by the primary packages.

### Dependencies for pydantic

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| annotated-types | 0.7.0 | MIT License | Reusable constraint types to use with typing.Annotated |
| pydantic-core | 2.41.5 | MIT | Core functionality for Pydantic validation and serialization |
```

### CycloneDX JSON format

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tools": [
      {
        "name": "uv-sbom",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "description": "HTTP library for Python",
      "licenses": [
        {
          "license": {
            "name": "Apache 2.0"
          }
        }
      ],
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```

## Requirements

- A Python project managed by `uv` with a `uv.lock` file
- Internet connection for fetching license information from PyPI

## Network Requirements

### External Domains Accessed

`uv-sbom` makes HTTP requests to the following external services during SBOM generation:

#### Required for all operations:

1. **PyPI (Python Package Index)**
   - Domain: `https://pypi.org`
   - Purpose: Fetch license information for Python packages
   - When: Every SBOM generation (unless using `--dry-run`)
   - Rate limit: No official limit, but tool implements retry logic
   - Endpoint: `/pypi/{package_name}/json`

#### Optional (only when using `--no-check-cve` disables CVE, or `--verify-links`):

2. **PyPI Link Verification**
   - Domain: `https://pypi.org`
   - Purpose: Verify package existence on PyPI via HTTP HEAD requests
   - When: Only when `--verify-links` flag is used
   - Rate limit: Max 10 concurrent requests
   - Endpoint: `/project/{package_name}/`

3. **OSV (Open Source Vulnerability Database)**
   - Domain: `https://api.osv.dev`
   - Purpose: Fetch vulnerability information for security scanning
   - When: By default (unless `--no-check-cve` is used)
   - Rate limit: Tool implements 10 requests/second limit
   - Endpoints:
     - `/v1/querybatch` - Batch query for vulnerability IDs
     - `/v1/vulns/{vuln_id}` - Detailed vulnerability information

4. **FIRST.org EPSS API**
   - Domain: `https://api.first.org`
   - Purpose: Fetch EPSS (Exploit Prediction Scoring System) scores and percentiles for CVEs
   - When: Only when `--check-exploitability` flag is used
   - Endpoint: `/data/v1/epss?cve=CVE-A,CVE-B,...` (batched)

5. **CISA KEV (Known Exploited Vulnerabilities) Catalog**
   - Domain: `https://www.cisa.gov`
   - Purpose: Check whether CVEs have confirmed active exploitation
   - When: Only when `--check-exploitability` flag is used
   - Endpoint: `/sites/default/files/feeds/known_exploited_vulnerabilities.json`

### Firewall Configuration

If you are behind a corporate firewall or proxy, ensure the following domains are on the allowlist:

```
# Required
pypi.org

# Optional (for --verify-links only; OSV is accessed by default unless --no-check-cve)
pypi.org       # Also used for --verify-links
api.osv.dev    # Disabled only with --no-check-cve

# Optional (for --check-exploitability only)
api.first.org  # EPSS scores
www.cisa.gov   # CISA KEV catalog
```

### Proxy Configuration

The tool respects standard HTTP/HTTPS proxy environment variables:

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

uv-sbom --format json
```

### Offline Mode

To validate configuration without making network requests, use `--dry-run`:

```bash
uv-sbom --dry-run
```

This mode:
- Validates `uv.lock` file
- Validates command-line arguments
- Checks exclude patterns
- Skips license fetching (no PyPI access)
- Skips vulnerability checking (no OSV access)
- Skips SBOM output generation

## Error Handling

uv-sbom provides detailed error messages with helpful suggestions:

- **Missing uv.lock file**: Clear message with suggestions on how to fix
- **Invalid project path**: Validates directory existence before processing
- **License fetch failures**: Retries failed requests (up to 3 attempts) and continues processing
- **File write errors**: Checks directory existence and permissions
- **Progress tracking**: Shows real-time progress during license information retrieval

Example error message:
```
❌ An error occurred:

uv.lock file not found: /path/to/project/uv.lock

💡 Hint: uv.lock file does not exist in project directory "/path/to/project".
   Please run in the root directory of a uv project, or specify the correct path with the --path option.
```

## Troubleshooting

### uv.lock file not found
Ensure you're running the command in a directory containing a `uv.lock` file, or use the `--path` option to specify the correct project directory.

### License information fetch failures
Some packages may fail to retrieve license information from PyPI. The tool will:
1. Automatically retry up to 3 times
2. Continue processing other packages
3. Display warnings for failed packages
4. Include packages in the output without license information if fetching fails

### Network issues
If you're behind a proxy or firewall, ensure that you can access `https://pypi.org`. The tool uses a 10-second timeout for API requests.

## For Developers

### Architecture

uv-sbom is built with **Hexagonal Architecture** (Ports and Adapters) + **Domain-Driven Design (DDD)** for maintainability and testability.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full breakdown of layers, ports, adapters, and architectural decision records (ADRs).

### Test Coverage

The test suite covers Unit, Integration, and End-to-End scenarios.

See [DEVELOPMENT.md](DEVELOPMENT.md) for how to run tests and contribute.

### Development Setup

After cloning the repository, activate the git hooks:

```bash
make setup
```

This enables `pre-commit` (auto-format) and `pre-push` (fmt check, clippy, tests) hooks from `.githooks/`, ensuring code quality checks run automatically for all contributors.

### Reference

- [DEVELOPMENT.md](DEVELOPMENT.md) — Development guide
- [ARCHITECTURE.md](ARCHITECTURE.md) — Hexagonal Architecture + DDD implementation details
- [CHANGELOG.md](CHANGELOG.md) — Change history
- [.claude/project-context.md](.claude/project-context.md) — Complete project context for Claude Code
- [.claude/instructions.md](.claude/instructions.md) — Coding guidelines and instructions for Claude Code

## Attribution

### Vulnerability Data

By default, this tool retrieves vulnerability data from [OSV (Open Source Vulnerability)](https://osv.dev), which is provided under the [Creative Commons Attribution 4.0 International License (CC-BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Use `--no-check-cve` to opt out of vulnerability checking.

**Required Attribution:**
- Vulnerability data provided by OSV
- Available at: https://osv.dev
- License: CC-BY 4.0

The OSV database is a collaborative effort to provide comprehensive, accurate, and accessible vulnerability information for open source software.

### Exploitability Data

When `--check-exploitability` is used, this tool retrieves data from:

- **EPSS (Exploit Prediction Scoring System)** by [FIRST.org](https://www.first.org/epss/) — probabilistic scoring of CVE exploitation likelihood. See EPSS at https://www.first.org/epss
- **CISA KEV (Known Exploited Vulnerabilities)** catalog by [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — authoritative list of CVEs with confirmed active exploitation (public domain, CC0)

## License

MIT License - see [LICENSE](LICENSE) file for details.

[shield_license]: https://img.shields.io/badge/license-MIT-blue.svg
[license_file]: LICENSE
