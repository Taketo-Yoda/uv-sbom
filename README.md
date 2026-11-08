# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![GitHub Downloads](https://img.shields.io/github/downloads/Taketo-Yoda/uv-sbom/total?logo=github&logoColor=white)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=pypi&logoColor=white)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom) [![Crates.io Downloads](https://img.shields.io/crates/d/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/dependabot/dependabot-updates) [![CodeQL](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/github-code-scanning/codeql)

[English](README.md) | [日本語](README-JP.md)

----

**Human-readable SBOMs with actionable supply chain insights for Python projects managed by [uv](https://github.com/astral-sh/uv).**

uv-sbom reads your `uv.lock` and generates a Markdown or CycloneDX 1.6 JSON SBOM focused on production runtime dependencies — then layers on vulnerability scanning, license compliance, incident response, and a suite of supply chain health checks, all in one command.

## What It Does

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

A single run produces a component inventory, a vulnerability report with resolution guidance, and upgrade recommendations:

```markdown
## Summary

| Item | Count | Status |
|------|-------|--------|
| Direct dependencies | 2 | ✅ |
| Transitive dependencies | 9 | ✅ |
| Vulnerabilities (above threshold) | 32 | ❌ |

## Vulnerability Report

| Package | Current Version | Fixed Version | CVSS | Severity | Vulnerability ID |
|---------|-----------------|---------------|------|----------|------------------|
| urllib3 | 2.0.4 | 2.6.3 | 7.5 | 🟠 HIGH | GHSA-38jv-5279-wg99 |
| h11 | 0.14.0 | 0.16.0 | 9.1 | 🔴 CRITICAL | GHSA-vqfr-h8mv-ghfj |
| ...

## Vulnerability Resolution Guide

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action |
|--------------------|---------|---------------|----------|---------------------------|-------------------|
| urllib3 | 2.0.4 | 2.0.6 | 🟡 MEDIUM | requests (2.31.0) | ⬆️ Upgrade requests → 2.32.3 |
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 |
```

## Why uv-sbom?

- **uv.lock-native** — Reads `uv.lock` directly, capturing only production runtime dependencies. No virtual environment needed, no build-time noise.
- **Markdown-first, actionable output** — Tables you can read, copy into a PR, or drop into a report. Every vulnerability shows which direct dependency introduced it, with the full dependency chain.
- **All-in-one supply chain coverage** — CVE scanning, license compliance, abandoned package detection, non-PyPI source detection, Python version compatibility, exploitability prioritization (EPSS + CISA KEV), incident response, and dependency diff — in a single tool.

## Quick Start

### Installation

```bash
# Cargo (Rust users)
cargo install uv-sbom

# uv tool (Python users)
uv tool install uv-sbom-bin

# pip
pip install uv-sbom-bin
```

Pre-built binaries are available on the [GitHub Releases](https://github.com/Taketo-Yoda/uv-sbom/releases) page for macOS (Apple Silicon, Intel), Linux (x86_64), and Windows.

### Basic Commands

```bash
# Generate a Markdown SBOM with vulnerability scanning (CVE check is on by default)
uv-sbom --format markdown --output SBOM.md

# Generate a CycloneDX JSON SBOM (current default; changes to Markdown in v5.0.0)
uv-sbom --format json --output sbom.json

# Check a specific advisory: am I affected, is the fix out, what do I run?
uv-sbom --incident GHSA-v845-jxx5-vc9f
```

> **Note (v5.0.0):** JSON is still the default output format in this release, but it will change to Markdown in v5.0.0. When neither `--format` nor the config file's `format` key is set, uv-sbom prints a deprecation warning on stderr (stdout is unchanged). To keep JSON output, pass `--format json` or set `format: json` in your config file. [Configuration →](docs/configuration.md)

### Output Language

```bash
# Japanese Markdown output
uv-sbom --format markdown --lang ja
```

Supported values: `en` (default), `ja`. The `--lang` option affects section headers, table column names, and status labels. Package names, CVE IDs, and SPDX identifiers always remain in their original form.

## Feature Highlights

### SBOM Generation

Generate a complete Software Bill of Materials from your `uv.lock` in Markdown or CycloneDX 1.6 JSON. The Markdown output clearly separates direct and transitive dependencies with license, description, and SHA-256 data for every package. [Output examples →](docs/cli-reference.md#output-examples)

### Security Scanning

CVE vulnerability checking via the [OSV database](https://osv.dev) is **enabled by default**. Filter by severity or CVSS threshold, suppress accepted findings with a vulnerability baseline, and get a resolution guide showing which direct dependency to upgrade. [Security checks →](docs/security-checks.md)

### Incident Response (`--incident`)

When a new advisory drops, one command tells you whether your project is affected, whether the fix is on PyPI yet, and gives you a dry-run-verified `uv lock --upgrade-package` command to run — or guidance when the upgrade can't resolve. Exit codes make it easy to script waiting for a patch. [Incident response →](docs/incident-response.md)

### Supply Chain Checks

- **License compliance** (`--check-license`) — Allow/deny lists with wildcard support. [Details →](docs/security-checks.md#license-compliance-check)
- **Abandoned package detection** (`--check-abandoned`) — Flags packages with no PyPI release within a configurable threshold. [Details →](docs/security-checks.md#abandoned-package-detection)
- **Non-PyPI source detection** (`--check-non-pypi`) — Identifies git, URL, and private registry sources. [Details →](docs/security-checks.md#non-pypi-source-detection)
- **Python version compatibility** (`--target-python`) — Checks `Requires-Python` constraints against a target version. [Details →](docs/security-checks.md#python-version-compatibility-check)
- **Exploitability prioritization** (`--check-exploitability`) — Enriches CVEs with EPSS scores and CISA KEV status. [Details →](docs/security-checks.md#exploitability-prioritization---check-exploitability)

### Dependency Insight

- **Explain** (`--explain <PACKAGE>`) — Trace every path from a direct dependency to any package. [Details →](docs/dependency-insight.md#dependency-explanation---explain)
- **Tree** (`--show-dependency-tree`) — ASCII tree visualization of your dependency graph. [Details →](docs/dependency-insight.md#dependency-tree-visualization---show-dependency-tree)
- **Diff** (`--diff <REF>`) — Compare lock file versions with a CVE delta. [Details →](docs/dependency-insight.md#dependency-diff---diff)

### Workspace Support

`--workspace` generates a per-member SBOM with an aggregate summary across all workspace members. [Workspace →](docs/workspace.md)

### CI Integration

Structured exit codes, severity/CVSS thresholds, and ready-to-use GitHub Actions and GitLab CI examples. [CI integration →](docs/ci-integration.md)

### Configuration

A `uv-sbom.config.yml` file sets defaults for all options. Generate a template with `--init`. CLI arguments always take precedence. [Configuration →](docs/configuration.md)

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

The official cyclonedx-python library reads from `.venv` and does not support `uv.lock`. uv itself can export CycloneDX SBOMs via `uv export --format cyclonedx1.5`. When generating SBOMs for Python projects:

| Aspect | uv-sbom (this tool) | CycloneDX Official Tools |
|--------|---------------------|--------------------------|
| **Data Source** | `uv.lock` file | `.venv` virtual environment |
| **Scope** | Production runtime dependencies only | Entire supply chain including build/dev tools |
| **Package Count** | Typically fewer (e.g., 16 packages) | Typically more (e.g., 38+ packages) |
| **Use Case** | Production security scanning | Comprehensive supply chain audit |
| **Accuracy** | Reflects locked dependencies | Reflects installed packages |

### Which Tool Should You Use?

- **For production security scanning**: Use `uv-sbom` to focus on dependencies that will be deployed to production, with Markdown reports, CVE checking, and upgrade paths
- **For CycloneDX SBOM from uv.lock**: Use `uv export --format cyclonedx1.5` for a CycloneDX-format SBOM generated directly from your lockfile
- **For comprehensive supply chain audit**: Use CycloneDX official tools to include all development and build-time dependencies from the installed environment
- **For regulatory compliance**: Check your specific requirements - some regulations may require the comprehensive approach

The focused approach of `uv-sbom` reduces noise in security vulnerability scanning by excluding build-time dependencies that don't ship with the final application.

## Documentation

| Document | Description |
|----------|-------------|
| [Security Checks](docs/security-checks.md) | CVE scanning, thresholds, baseline, license, abandoned, non-PyPI, Python compat, exploitability |
| [Incident Response](docs/incident-response.md) | `--incident` mode: advisory lookup, workspace, manual range, exit codes, wait-for-patch |
| [Dependency Insight](docs/dependency-insight.md) | `--explain`, `--show-dependency-tree`, `--diff`, resolution guide, upgrade advisor |
| [Configuration](docs/configuration.md) | Config file, schema reference, merge rules, exclude patterns, dependency groups |
| [CI Integration](docs/ci-integration.md) | GitHub Actions, GitLab CI, exit codes, scripting, error handling |
| [Workspace](docs/workspace.md) | `--workspace` mode, aggregate summary, root dependency groups |
| [Network](docs/network.md) | External domains, firewall, proxy, offline mode |
| [CLI Reference](docs/cli-reference.md) | Full command-line options, output format examples |

## Requirements

- A Python project managed by `uv` with a `uv.lock` file
- Internet connection for fetching license information from PyPI

## For Developers

### Architecture

uv-sbom is built with **Hexagonal Architecture** (Ports and Adapters) + **Domain-Driven Design (DDD)** for maintainability and testability.

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full breakdown of layers, ports, adapters, and architectural decision records (ADRs).

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
