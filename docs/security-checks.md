# Security Checks

[Back to README](../README.md)

uv-sbom provides a comprehensive suite of security and supply chain checks that run alongside SBOM generation. This document covers every check, its configuration, and its output format.

## Table of Contents

- [Checking for Vulnerabilities](#checking-for-vulnerabilities)
- [Disabling CVE Checking](#disabling-cve-checking)
- [Vulnerability Threshold Options](#vulnerability-threshold-options)
- [Malicious Packages](#malicious-packages)
- [Vulnerability Baseline](#vulnerability-baseline)
- [License Compliance Check](#license-compliance-check)
- [Abandoned Package Detection](#abandoned-package-detection)
- [Non-PyPI Source Detection](#non-pypi-source-detection)
- [Python Version Compatibility Check](#python-version-compatibility-check)
- [Exploitability Prioritization (`--check-exploitability`)](#exploitability-prioritization---check-exploitability)
- [PyPI Link Verification](#pypi-link-verification)
- [Exclude Pattern Input Validation](#exclude-pattern-input-validation)

---

## Checking for Vulnerabilities

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

## Disabling CVE Checking

CVE vulnerability checking is enabled by default. To opt out, use the `--no-check-cve` flag:

```bash
# Generate SBOM without CVE checking
uv-sbom --format markdown --no-check-cve

# Disable via config file
# check_cve: false  (in uv-sbom.config.yml)
```

> **Note:** `--no-check-cve` conflicts with `--severity-threshold`, `--cvss-threshold`, and `--suggest-fix`.

## Vulnerability Threshold Options

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

## Malicious Packages

OSV malicious-package advisories (IDs starting with `MAL-`, either as the primary ID or as an alias) always fail the run with exit code 1, regardless of `--severity-threshold` or `--cvss-threshold`. Malware has no CVSS score, so it would otherwise fall below every threshold. These advisories are never written to a [vulnerability baseline](#vulnerability-baseline), and an existing baseline entry for one does not suppress it. To accept one deliberately, ignore it by its exact primary ID with `--ignore-cve` or `ignore_cves`. In the Markdown report, they are listed in a dedicated block at the top of the vulnerability section, with each advisory's summary and an instruction to remove the package, and are not repeated in the regular vulnerability tables.

## Vulnerability Baseline

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

**`--update-baseline`** rewrites the baseline file with all current (unfiltered) findings. Use it when you accept a new batch of known CVEs. Requires `--baseline`. Malicious-package advisories (`MAL-`) are never recorded and never suppressed; see [Malicious Packages](#malicious-packages).

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

## License Compliance Check

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

**Example output:**

```markdown
## License Compliance Check

Policy: 3 allowed patterns, 1 denied pattern | Unknown: warn

### Violations (2 found)

| Package | Version | License | Reason |
|---------|---------|---------|--------|
| some-gpl-lib | 1.0.0 | GPL-3.0 | Denied by policy |
| mystery-pkg | 2.1.0 | Unknown | Not in allow list |
```

## Abandoned Package Detection

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

See [`examples/abandoned-packages-project/README.md`](../examples/abandoned-packages-project/README.md) for a full walkthrough.

## Non-PyPI Source Detection

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

See [`examples/non-pypi-sources-project/README.md`](../examples/non-pypi-sources-project/README.md) for a full walkthrough.

## Python Version Compatibility Check

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

Produced by running against [`examples/sample-project`](../examples/sample-project):

```bash
uv-sbom -p examples/sample-project --target-python 3.8 --no-check-cve -f markdown
```

**Config file equivalent:**
```yaml
target_python: "3.8"
```

## Exploitability Prioritization (`--check-exploitability`)

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

Produced by running against [`examples/suggest-fix-project`](../examples/suggest-fix-project):

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

## PyPI Link Verification

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

## Exclude Pattern Input Validation

The `-e`/`--exclude` option implements the following security measures to protect against malicious input:

### Character Restrictions

Only the following characters are allowed in patterns:
- **Alphanumeric characters**: a-z, A-Z, 0-9, Unicode letters/numbers
- **Hyphens** (`-`), **underscores** (`_`), **dots** (`.`): Common in package names
- **Square brackets** (`[`, `]`): For package extras (e.g., `requests[security]`)
- **Asterisks** (`*`): For wildcard matching

Control characters, shell metacharacters, and path separators are blocked to prevent:
- Terminal escape sequence injection
- Log injection attacks
- Command injection (defense in depth)

### Pattern Limits

- **Maximum patterns**: 64 patterns can be specified per invocation
- **Maximum length**: 255 characters per pattern
- **Minimum content**: Patterns must contain at least one non-wildcard character

These limits prevent denial-of-service attacks via:
- Excessive memory consumption
- CPU exhaustion from complex pattern matching

### Examples

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

For more detailed security information, including threat model and attack vectors, see [SECURITY.md](../SECURITY.md).
