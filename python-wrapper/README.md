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
- **Vulnerability scanning** - Check for known CVEs using OSV API with `--check-cve`
- **Configurable thresholds** - Filter vulnerabilities by severity or CVSS score
- **Package exclusion** - Exclude internal packages with `--exclude` patterns
- **Configuration file support** - Define defaults in `uv-sbom.config.yml`
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

```bash
# Check for all vulnerabilities
uv-sbom --format markdown --check-cve

# Check for High/Critical severity only
uv-sbom --format markdown --check-cve --severity-threshold high

# Check for CVSS >= 7.0
uv-sbom --format markdown --check-cve --cvss-threshold 7.0

# Ignore specific CVEs
uv-sbom --format markdown --check-cve --ignore-cve CVE-2024-1234
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
check_cve: true
severity_threshold: high
exclude_packages:
  - "pytest"
  - "*-dev"
ignore_cves:
  - id: CVE-2024-1234
    reason: "False positive for our use case"
```

Generate a template:

```bash
uv-sbom --init
```

### CI Integration

```yaml
# GitHub Actions example
- name: Security Check
  run: uv-sbom --format markdown --check-cve --severity-threshold high
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
