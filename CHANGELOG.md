# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-01-24

### 🎉 First Stable Release

This is the first stable release of uv-sbom, marking the tool as production-ready. All core features have been implemented and thoroughly tested (500+ tests).

### Added

#### Vulnerability Checking (OSV API Integration)
- **`--check-cve` option**: Check packages for known vulnerabilities using the [OSV.dev](https://osv.dev/) API
- **Severity threshold** (`--severity-threshold`): Filter vulnerabilities by severity level (low/medium/high/critical)
- **CVSS threshold** (`--cvss-threshold`): Filter vulnerabilities by CVSS score (0.0-10.0)
- **Exit code system**: 0 = OK, 1 = Vulnerabilities above threshold found, 3 = Application error
- **Progress indicator**: Visual progress bar during vulnerability checking
- **Warning/Info sections**: Enhanced Markdown output with threshold context

#### Performance & Reliability
- **Asynchronous processing**: Parallel license fetching from PyPI and vulnerability checking from OSV
- **License caching**: In-memory caching of PyPI license responses for repeated lookups
- **Severity parsing fallback**: Robust CVSS-to-severity mapping when API data is incomplete

#### Developer Experience
- **`--dry-run` option**: Validate configuration without generating SBOM
- **Agent Skills**: Automated workflow enforcement via `/commit`, `/pr`, `/issue`, `/implement` skills
- **Pre-commit hook**: Automatic `cargo fmt` on staged Rust files
- **Dependabot**: Automated dependency updates for Cargo and GitHub Actions

#### Documentation
- Exit codes and network requirements sections in README
- `--check-cve` documentation with OSV attribution
- Security measures documentation for exclude patterns
- Comprehensive vulnerability threshold documentation (English and Japanese)

### Changed

#### Architecture Improvements
- **CheckVulnerabilitiesUseCase**: Consolidated vulnerability checking logic in dedicated use case
- **SbomRequestBuilder pattern**: Cleaner, more intuitive API for SBOM generation
- **Async refactoring**: `GenerateSbomUseCase`, `PyPiLicenseRepository`, and `OsvClient` now async

#### CI/CD Improvements
- GitHub Actions updated: checkout v6, upload-artifact v6, download-artifact v7, cache v5, setup-python v6
- Explicit workflow permissions for security
- Documentation-only changes skip CI runs

#### Code Quality
- Removed all unused dead_code (YAGNI compliance)
- Split large methods into smaller, focused functions
- Extracted test modules for better organization

### Fixed
- Severity parsing with API fallback strategy when CVSS data is incomplete
- CI workflow permissions for artifact uploads

### Dependencies
- `toml`: 0.8.23 → 0.9.11
- `reqwest`: 0.12.28 → 0.13.1
- `indicatif`: 0.17.11 → 0.18.3

## [0.2.0] - 2025-01-06

### Added

#### CLI UX Improvements
- **Startup banner**: Colorful banner displaying version (🚀 uv-sbom v0.2.0) at the start of execution
- **Rich progress bar**: Dynamic progress bar using `indicatif` crate with spinner, percentage, and message display
- **Terminal colors**: Added `owo-colors` crate for enhanced terminal output

#### Features
- **Package exclusion**: Added `--exclude` / `-e` option to filter packages from SBOM output (#1)
  - Support for wildcard patterns (`*`) for flexible matching
  - Can specify multiple exclusion patterns
  - Maximum 64 patterns per invocation

#### Documentation
- **Status badges**: Added GitHub release, PyPI version, crates.io version, and CI status badges to README files (#15)
- **Version update checklist**: Added comprehensive checklist in `.claude/project-context.md` for future version updates

### Changed

#### Version Management
- **Dynamic version references**: Removed hardcoded versions from `src/cli.rs` - now uses `env!("CARGO_PKG_VERSION")` automatically
- **Dynamic User-Agent**: PyPI client now generates User-Agent string dynamically from package version
- **Documentation URLs**: Updated README installation instructions to use `/latest/download/` URLs for always getting the latest release
- **Tag format**: Standardized to `vX.Y.Z` format (removed deprecated `py-vX.Y.Z` format in documentation)

#### Refactoring
- **Strategy Pattern**: Applied Strategy Pattern to formatter selection for better maintainability (#9)
- **Factory Pattern**: Moved formatter and presenter creation to application layer
- **OutputFormat consolidation**: Moved OutputFormat from ports to application layer

#### CI/CD Improvements
- **Workflow consolidation**: Consolidated release and PyPI publish workflows
- **Concurrency control**: Added concurrency control to prevent duplicate workflow runs
- **Cache optimization**: Updated to cache v4 for better performance
- **All-branch CI**: Enabled CI workflow on all branches for better testing coverage

#### Documentation Updates
- **Architecture docs**: Simplified directory structure and abstracted implementation details
- **Distribution guide**: Updated with current CD practices and removed outdated version references
- **Development guide**: Added Git branch strategy documentation
- **Project context**: Removed hardcoded test counts and updated structure

### Fixed
- **README-JP.md**: Fixed typo in link syntax

## [0.1.0] - 2025-01-02

### Added

#### Core Features
- Parse `uv.lock` files to extract dependency information
- Fetch license information from PyPI with intelligent fallback and retry logic
- Generate **CycloneDX 1.6** JSON format output (standard SBOM format)
- Generate **Markdown** table format output with dependency analysis
- Dependency graph analysis (direct vs transitive dependencies)
- Progress tracking during license information retrieval
- Rate limiting for PyPI API calls (10 req/sec to prevent DoS)

#### CLI Features
- Command-line interface with intuitive options
- Multiple output formats: JSON (CycloneDX) and Markdown
- Flexible path specification (`--path` option)
- File output or stdout (`--output` option)
- Comprehensive `--help` documentation

#### Architecture & Code Quality
- **Hexagonal Architecture** (Ports & Adapters) + **Domain-Driven Design**
- Clean separation of concerns across layers (Domain, Application, Ports, Adapters)
- Generic-based dependency injection for testability
- Comprehensive test coverage (Unit, Integration, E2E)
- Zero Clippy warnings

#### Security Features
- File security validation (symlink protection, file size limits)
- TOCTOU attack mitigation for file operations
- Rate limiting to prevent DoS via unbounded API requests
- Input validation at domain boundaries
- Secure error handling (no sensitive information leakage)

#### Developer Experience
- Detailed error messages with actionable suggestions
- Robust error recovery (continues on license fetch failures)
- Progress reporting for long-running operations
- Clean, documented code with comprehensive examples

### Documentation
- Comprehensive README with usage examples and troubleshooting
- ARCHITECTURE.md explaining hexagonal architecture implementation
- DEVELOPMENT.md for contributors
- Claude Code integration files (`.claude/` directory)
- Inline code documentation for all public APIs
