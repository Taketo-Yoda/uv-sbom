# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-03-21

### Security
- Updated `aws-lc-sys` to 0.39.0 to fix GHSA-394x-vwmw-crm3 and GHSA-9f94-5g5w-gf6r

## [2.0.0] - 2026-03-15

### Breaking Changes
- **CVE check is now enabled by default**: Previously opt-in via `--check-cve`; now opt-out via `--no-check-cve` (#307)

### Added

#### Internationalization (--lang)
- **`--lang` CLI flag**: Switch output language between English (`en`) and Japanese (`ja`) (#293)
- **`Locale` enum and `Messages` struct**: Foundation for multilingual support (#292)
- **Localized `MarkdownFormatter`**: All Markdown output respects the selected locale (#294, #309)
- **Localized stderr progress and warning messages**: Progress output in `GenerateSbomUseCase` respects locale (#295, #308)
- **Localized transitive deps sub-header and vulnerability summary line** (#318)
- **E2E tests for `--lang` option** (#306, #319)
- **Integration tests and README docs for `--lang` option** (#296, #303)

### Changed
- **`--no-check-cve` flag**: Added as opt-out replacement; CVE check runs by default (#307)

## [1.3.0] - 2026-03-07

### Added

#### Upgrade Advisor (--suggest-fix)
- **`--suggest-fix` CLI flag**: New flag to suggest package upgrades that resolve known vulnerabilities (#265, #271)
- **`UvLockSimulator` outbound port**: Defines the port interface for uv lock simulation (#249)
- **`UvLockAdapter`**: Implements uv lock simulation by invoking `uv lock` with version constraints (#250)
- **`UpgradeRecommendation` domain model**: Enum representing upgrade simulation outcomes (#251)
- **`UpgradeAdvisor` domain service**: Simulates per-package version upgrades to find vulnerability-resolving versions (#252)
- **`GenerateSbomUseCase` integration**: Wires UpgradeAdvisor into the main use case pipeline (#254)
- **Formatter extensions**: Markdown and CycloneDX formatters now render upgrade recommendations (#255)
- **Progress reporting**: Report progress during `--suggest-fix` upgrade simulations (#284)

### Changed
- Pre-flight validation enforces `--suggest-fix` requires `--check-cve` (#256)
- `--suggest-fix` is now configurable via config file (#282)

### Testing
- Fixture-based and empty-input tests for UpgradeAdvisor and formatters (#257)

### Documentation
- README and README-JP updated to document `--suggest-fix` flag (#258, #273)

### Dependencies
- Bumped 3 Cargo dependencies
- `actions/upload-artifact`: 6 → 7
- `actions/download-artifact`: 7 → 8

## [1.2.0] - 2026-02-19

### Added

#### License Compliance
- **`--check-license` option**: License compliance policy check to detect restricted licenses (#227)

#### Vulnerability Resolution Guide
- **Resolution Guide domain models**: `ResolutionEntry` and `IntroducedBy` domain models (#229)
- **`ResolutionAnalyzer` domain service**: Analyze dependency trees to generate resolution guidance (#230)
- **Resolution Guide application layer**: View model and builder logic for resolution guides (#231)
- **Resolution Guide formatters**: Render resolution guide in Markdown and CycloneDX output (#232)

#### CycloneDX Enhancements
- **Component group field**: Add group field to CycloneDX components (#241)
- **SPDX license ID mapping**: Map license strings to standard SPDX license identifiers (#241)
- **Package hashes**: Include package hashes from PyPI in CycloneDX output (#242)
- **`metadata.component`**: Add metadata component section to CycloneDX BOM (#242)

### Changed

#### Architecture Improvements
- **`SbomResponseBuilder` pattern**: Cleaner response construction replacing direct assembly (#68, #233)

#### Documentation
- Add `--check-license` feature documentation to README files
- Add Vulnerability Resolution Guide documentation to README files

### Dependencies
- `toml`: 0.9.11+spec-1.1.0 → 1.0.1+spec-1.1.0
- Dependencies group updates (4 packages)

## [1.1.0] - 2026-02-06

### Added

#### Config File Support
- **`--config` option**: Load settings from YAML configuration file
- **`--ignore-cve` option**: Ignore specific CVEs from vulnerability checks
- **`--init` option**: Generate config file template for quick setup
- **`--verify-links` flag**: Validate that PyPI package URLs actually exist

#### Output Enhancements
- **PyPI hyperlinks**: Package names link directly to PyPI in Markdown output
- **CVE hyperlinks**: Vulnerability IDs link to OSV/GHSA/CVE sources

#### Developer Experience
- **`/dependabot` skill**: Standardized workflow for handling Dependabot security alerts
- **`/release` skill**: Standardized release preparation workflow
- **`AGENTS.md`**: Codebase context documentation for AI-assisted development

### Fixed
- **Dependency classification**: Preserve dependency classification when root project is excluded (#213)
- **Vulnerable dependency**: Replace vulnerable `serde_yml` with `serde_yaml_ng` (#199)

### Changed

#### Architecture Improvements
- **`SbomReadModel` and `SbomReadModelBuilder`**: Cleaner formatting pipeline
- **`format_v2` method**: Replacing legacy format methods
- **`thiserror` crate**: Better error handling with derive macros
- **Semantic methods**: Added semantic methods in `VulnerabilityCheckResult`

#### Documentation
- README updates for config file, CVE ignore, and `--verify-links` features
- Japanese README kept in sync with English README

### Dependencies
- `bytes`: 1.11.0 → 1.11.1
- `thiserror`: 1.0.69 → 2.0.17
- `serde_yml` replaced with `serde_yaml_ng` (security fix)
- Other dependency group updates

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
