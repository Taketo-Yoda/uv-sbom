# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
