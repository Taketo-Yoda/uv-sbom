# uv-sbom-bin

[![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white)](https://pypi.org/project/uv-sbom-bin/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=pypi&logoColor=white)](https://pypi.org/project/uv-sbom-bin/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Taketo-Yoda/uv-sbom/blob/main/LICENSE)
[![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)

Python wrapper for the `uv-sbom` CLI tool written in Rust.

Generate SBOMs (Software Bill of Materials) for Python projects managed by [uv](https://github.com/astral-sh/uv).

## Features

- **Fast and standalone** - Written in Rust, no Python dependencies required at runtime
- **Multiple output formats** - CycloneDX 1.6 JSON (standard) and Markdown (human-readable)
- **Vulnerability scanning** - CVE checking via OSV API is **enabled by default**; use `--no-check-cve` to opt out
- **Configurable thresholds** - Filter vulnerabilities by severity or CVSS score
- **Package exclusion** - Exclude internal packages with `--exclude` patterns
- **Configuration file support** - Define defaults in `uv-sbom.config.yml`
- **License compliance** - Enforce license policies with allow/deny lists via `--check-license`
- **CI/CD ready** - Exit codes for easy integration into pipelines
- **License detection** - Automatically fetches license info from PyPI

## Why uv-sbom?

Unlike other SBOM tools that scan the entire virtual environment, `uv-sbom` focuses on **production runtime dependencies** from `uv.lock`:

| Aspect | uv-sbom | CycloneDX Official Tools |
|--------|---------|--------------------------|
| **Data Source** | `uv.lock` file | `.venv` virtual environment |
| **Scope** | Production dependencies only | Entire supply chain |
| **Package Count** | Fewer (e.g., 16 packages) | More (e.g., 38+ packages) |
| **Use Case** | Production security scanning | Comprehensive audit |

This focused approach reduces noise in security scanning by excluding build-time dependencies that don't ship with your application.

## Installation

### Via uv (Recommended)

```bash
uv tool install uv-sbom-bin
```

### Via pip

```bash
pip install uv-sbom-bin
```

After installation, the `uv-sbom` command will be available in your PATH.

> **Note**: The package name is `uv-sbom-bin`, but the installed command is `uv-sbom`.

## Usage

### Basic Commands

```bash
# Show version
uv-sbom --version

# Generate CycloneDX JSON SBOM (default)
uv-sbom --format json

# Generate Markdown SBOM
uv-sbom --format markdown --output SBOM.md
```

### Vulnerability Checking

CVE checking is **enabled by default**. Use `--no-check-cve` to opt out.

```bash
# Check for all vulnerabilities (default — no flag needed)
uv-sbom --format markdown

# Check for High/Critical severity only
uv-sbom --format markdown --severity-threshold high

# Check for CVSS >= 7.0
uv-sbom --format markdown --cvss-threshold 7.0

# Ignore specific CVEs
uv-sbom --format markdown --ignore-cve CVE-2024-1234

# Disable CVE checking
uv-sbom --format markdown --no-check-cve
```

### License Compliance Check

```bash
# License compliance check
uv-sbom --check-license --license-allow "MIT,Apache-2.0,BSD-*"

# Combined with vulnerability check (CVE enabled by default)
uv-sbom --check-license --severity-threshold high
```

### Excluding Packages

```bash
# Exclude specific packages
uv-sbom -e "pytest" -e "mypy"

# Exclude with wildcards
uv-sbom -e "*-dev" -e "debug-*"
```

### Configuration File

Create a `uv-sbom.config.yml` file in your project directory:

```yaml
format: markdown
# check_cve: true  # CVE checking is enabled by default; set to false to disable
severity_threshold: high
exclude_packages:
  - "pytest"
  - "*-dev"
ignore_cves:
  - id: CVE-2024-1234
    reason: "False positive for our use case"
license_policy:
  allow: ["MIT", "Apache-2.0", "BSD-*"]
  deny: ["GPL-3.0-only", "AGPL-*"]
  unknown: "warn"
```

Generate a template:

```bash
uv-sbom --init
```

### CI Integration

```yaml
# GitHub Actions example (CVE checking is enabled by default)
- name: Security Check
  run: uv-sbom --format markdown --severity-threshold high
```

## Output Example

Markdown format with vulnerability report:

```markdown
# Software Bill of Materials (SBOM)

## Component Inventory

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| requests | 2.31.0 | Apache 2.0 | HTTP library for Python |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |

## Vulnerability Report

| Package | Current | Fixed | CVSS | Severity | CVE ID |
|---------|---------|-------|------|----------|--------|
| urllib3 | 2.0.0 | 2.0.7 | 9.8 | CRITICAL | CVE-2023-45803 |
```

## How It Works

This package downloads the prebuilt Rust binary for your platform from the [GitHub releases](https://github.com/Taketo-Yoda/uv-sbom/releases) and installs it.

**Supported platforms:**
- macOS (Apple Silicon and Intel)
- Linux (x86_64)
- Windows (x86_64)

## Full Documentation

For comprehensive documentation including:
- Complete command-line reference
- Security input validation details
- Network requirements and proxy configuration
- Exit codes and error handling
- Troubleshooting guide

Visit the main repository: **[uv-sbom on GitHub](https://github.com/Taketo-Yoda/uv-sbom)**

## License

MIT License - see [LICENSE](https://github.com/Taketo-Yoda/uv-sbom/blob/main/LICENSE)
