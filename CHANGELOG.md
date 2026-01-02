# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Comprehensive test coverage: **163 tests** (Unit, Integration, E2E)
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
