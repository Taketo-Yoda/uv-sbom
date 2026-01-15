# uv-sbom Project Context

This file provides complete project context for Claude Code and other developers.

## Project Overview

**uv-sbom** is a Rust-based CLI tool that generates SBOM (Software Bill of Materials) from projects managed by the Python package manager [uv](https://github.com/astral-sh/uv).

### Key Objectives
- Visualize uv project dependencies
- Generate SBOMs for security audits and compliance
- Automatically collect and report license information
- Analyze direct and transitive dependencies

### Version Information
- Current Version: 0.2.0
- Rust Edition: 2021
- CycloneDX Specification: 1.6
- Architecture: Hexagonal Architecture + DDD

### Version Update Checklist

When updating the version number, verify and update all of the following files:

#### Required Updates (Dynamic Version Reference)
These files automatically retrieve the version using `env!("CARGO_PKG_VERSION")` or similar mechanisms. Updating Cargo.toml will automatically reflect the changes:

1. **Cargo.toml** - `version = "X.Y.Z"` (Main version management)
2. **src/cli.rs** - `#[command(version)]` (Auto-retrieved from Cargo.toml)
3. **src/main.rs** - Uses `env!("CARGO_PKG_VERSION")` in `display_banner()` function
4. **src/adapters/outbound/network/pypi_client.rs** - Uses `env!("CARGO_PKG_VERSION")` in User-Agent

#### Python Wrapper Files (Manual Update Required)
5. **python-wrapper/pyproject.toml** - `version = "X.Y.Z"`
6. **python-wrapper/uv_sbom_bin/__init__.py** - `__version__ = "X.Y.Z"`
7. **python-wrapper/uv_sbom_bin/install.py** - `UV_SBOM_VERSION = "X.Y.Z"`

#### Documentation Files (Manual Update Required)
8. **.claude/project-context.md** - "Current Version" section in this file

#### Auto-generated/Sample Files (No Update Required)
The following files do **NOT** need updates:
- `Cargo.lock` - Auto-generated
- `CHANGELOG.md` - Kept as history
- `RELEASE.md` - Kept for release comparison URLs
- `README.md` / `README-JP.md` - Uses `/latest/download/` URL (version-independent)
- `docs/DISTRIBUTION_GUIDE.md` - Uses placeholder (X.Y.Z)
- `src/sbom_generation/domain/sbom_metadata.rs` - Test code (dynamically generated in practice)
- `examples/sample-project/pyproject.toml` - Sample project
- `docs/PYPI_WRAPPER_SETUP.md` - Listed as documentation example

#### Version Update Procedure
```bash
# 1. Update Cargo.toml version
sed -i '' 's/version = "0.2.0"/version = "0.3.0"/' Cargo.toml

# 2. Update Python wrapper version
sed -i '' 's/version = "0.2.0"/version = "0.3.0"/' python-wrapper/pyproject.toml
sed -i '' 's/__version__ = "0.2.0"/__version__ = "0.3.0"/' python-wrapper/uv_sbom_bin/__init__.py
sed -i '' 's/UV_SBOM_VERSION = "0.2.0"/UV_SBOM_VERSION = "0.3.0"/' python-wrapper/uv_sbom_bin/install.py

# 3. Update this file's version
sed -i '' 's/Current Version: 0.2.0/Current Version: 0.3.0/' .claude/project-context.md

# 4. Build and test
cargo build
cargo test

# 5. Commit
git add Cargo.toml python-wrapper/ .claude/project-context.md
git commit -m "chore: bump version to 0.3.0"
```

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

## Resources

### Documentation
- `README.md`: User guide
- `.claude/instructions.md`: Instructions for Claude Code
- `.claude/skills/`: Agent Skills for Git workflows (`/issue`, `/pr`, `/commit`, `/pre-push`)

### External References
- [CycloneDX 1.6 Specification](https://cyclonedx.org/docs/1.6/)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
- [uv](https://github.com/astral-sh/uv)

---

Last Updated: 2026-01-15
