# uv-sbom Project Context

This file provides complete project context for Claude Code and other developers.

## Project Overview

**uv-sbom** is a Rust-based CLI tool that generates SBOM (Software Bill of Materials) from projects managed by the Python package manager [uv](https://github.com/astral-sh/uv).

### Key Objectives
- Visualize uv project dependencies
- Generate SBOMs for security audits and compliance
- Automatically collect and report license information
- Analyze direct and transitive dependencies
- Check for known vulnerabilities with configurable thresholds for CI integration

### Version Information
- Rust Edition: 2021
- CycloneDX Specification: 1.6
- Architecture: Hexagonal Architecture + DDD

The release version lives in `Cargo.toml`. To change it, run `/release`, which bumps
the version files listed in `.claude/skills/release/SKILL.md` → "Step 3: Update
Version Files".

## Technology Stack

### Main Dependencies
```toml
# CLI & Configuration
clap = "4.5"                 # CLI argument parsing (using derive feature)

# Serialization
serde = "1.0"                # Serialization (using derive feature)
serde_json = "1.0"           # JSON processing
toml = "0.8"                 # TOML (uv.lock) parsing

# Error Handling
anyhow = "1.0"               # Error handling

# HTTP Client
reqwest = "0.12"             # HTTP client (using blocking feature)

# Utilities
chrono = "0.4"               # Date/time handling
uuid = "1.10"                # UUID generation (using v4 feature)

# Testing
tempfile = "3.8"             # Temporary file creation
```

## Architecture: Hexagonal Architecture + DDD

### Architecture Principles

This project adopts **Hexagonal Architecture (Ports & Adapters pattern)** and **Domain-Driven Design (DDD)**.

**Key Benefits**:
1. **Testability**: Domain logic is isolated from I/O, easily testable with mocks
2. **Maintainability**: Clear separation of concerns, easy to locate code
3. **Flexibility**: Infrastructure implementations can be easily swapped
4. **Screaming Architecture**: Directory structure expresses the system's purpose

### Layer Structure

The project consists of four main layers:

1. **Domain Layer** (`sbom_generation/`)
   - Pure business logic, no infrastructure dependencies
   - Value objects, aggregates, domain services, policies

2. **Application Layer** (`application/`)
   - Use case orchestration
   - DTOs (Data Transfer Objects), factories

3. **Ports Layer** (`ports/`)
   - Interface definitions (traits)
   - Inbound/outbound ports

4. **Adapters Layer** (`adapters/`)
   - Concrete infrastructure implementations
   - File system, network, formatters, console

5. **Shared Kernel** (`shared/`)
   - Error types, security validation, etc.

**Detailed Directory Structure**: See [ARCHITECTURE-JP.md](../ARCHITECTURE-JP.md)

### Key Features

#### Vulnerability Threshold Checking
The tool supports configurable vulnerability thresholds for CI/CD integration:

- **Severity Threshold** (`--severity-threshold`): Filter vulnerabilities by severity level
  - Values: `low`, `medium`, `high`, `critical`
  - Example: `--severity-threshold high` only triggers exit code 1 for High/Critical vulnerabilities

- **CVSS Threshold** (`--cvss-threshold`): Filter vulnerabilities by CVSS score
  - Values: `0.0` to `10.0`
  - Example: `--cvss-threshold 7.0` only triggers exit code 1 for CVSS >= 7.0

**Exit Code Behavior with Thresholds:**
| Scenario | Exit Code |
|----------|-----------|
| No vulnerabilities | 0 |
| Vulnerabilities below threshold | 0 |
| Vulnerabilities above threshold | 1 |

**Architecture Components:**
- `VulnerabilityChecker` (Domain Service): Pure business logic for threshold evaluation
- `CheckVulnerabilitiesUseCase` (Application Layer): Orchestrates the vulnerability check workflow

## Resources

### Documentation
- `README.md`: User guide
- `.claude/instructions.md`: Instructions for Claude Code
- `.claude/skills/`: Agent Skills for Git workflows (`/issue`, `/pr`, `/commit`, `/pre-push`)
- `.claude/product-vision.md`: Product vision and competitive positioning
- `.claude/output-design.md`: Output structure rules, anti-patterns, and formatting standards

### External References
- [CycloneDX 1.6 Specification](https://cyclonedx.org/docs/1.6/)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
- [uv](https://github.com/astral-sh/uv)

---

Last Updated: 2025-01-24
