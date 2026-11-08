# CI Integration

[Back to README](../README.md)

uv-sbom integrates into CI/CD pipelines with structured exit codes, threshold-based vulnerability gating, and ready-to-use workflow examples for GitHub Actions and GitLab CI.

## Table of Contents

- [CI Workflow Examples](#ci-workflow-examples)
- [Exit Codes](#exit-codes)
- [Exit Codes with Vulnerability and License Checking](#exit-codes-with-vulnerability-and-license-checking)
- [Common Error Scenarios](#common-error-scenarios)
- [Usage in Scripts](#usage-in-scripts)
- [Error Handling](#error-handling)
- [Troubleshooting](#troubleshooting)

---

## CI Workflow Examples

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

When no vulnerabilities are found:

```markdown
## Vulnerability Report

**✅ No Known Vulnerabilities**

No security vulnerabilities were found in the scanned packages.

---

*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*
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

## Exit Codes with Vulnerability and License Checking

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

## Common Error Scenarios

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

## Usage in Scripts

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
If you're behind a proxy or firewall, ensure that you can access `https://pypi.org`. The tool uses a 10-second timeout for API requests. See [Network Requirements](network.md) for firewall and proxy configuration.
