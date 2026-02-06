# AGENTS.md - Codebase Context for AI Agents

## 1. Project Overview

**Project:** `uv-sbom`
**Purpose:** CLI tool to generate SBOM (Software Bill of Materials) from Python projects managed by [uv](https://github.com/astral-sh/uv).

**Key Features:**
- Parse `uv.lock` and extract dependency information
- Fetch license info from PyPI API (with retry logic)
- Check known vulnerabilities via OSV API (Markdown format only)
- Output formats: CycloneDX 1.6 JSON, Markdown (with direct/transitive dependency separation)
- Standalone Rust binary, progress display, robust error handling

**Distribution:**
- Cargo: `cargo install uv-sbom`
- PyPI: `pip install uv-sbom-bin`
- GitHub Releases: macOS / Linux / Windows binaries

**Tech Stack:** Rust 2021 edition, Hexagonal Architecture + DDD

---

## 2. Directory Structure

```
uv-sbom/
├── src/
│   ├── main.rs                    # Entry point (DI wiring only)
│   ├── lib.rs                     # Library root (public API)
│   ├── cli.rs                     # CLI parsing (clap)
│   ├── config.rs                  # YAML config file support
│   ├── sbom_generation/           # Domain layer (pure business logic)
│   │   ├── domain/
│   │   │   ├── package.rs         # Package, PackageName, Version
│   │   │   ├── license_info.rs    # LicenseInfo value object
│   │   │   ├── dependency_graph.rs # DependencyGraph aggregate
│   │   │   ├── sbom_metadata.rs   # SbomMetadata (timestamp, UUID)
│   │   │   ├── vulnerability.rs   # Vulnerability, Severity, CvssScore
│   │   │   └── services/
│   │   │       └── vulnerability_checker.rs  # Threshold evaluation
│   │   ├── services/              # Domain services (pure functions)
│   │   │   ├── dependency_analyzer.rs  # Dependency analysis, cycle detection
│   │   │   ├── package_filter.rs       # Package filtering
│   │   │   └── sbom_generator.rs       # SBOM metadata generation
│   │   └── policies/
│   │       └── license_priority.rs     # License selection rules
│   ├── application/               # Application layer (use cases)
│   │   ├── use_cases/
│   │   │   ├── generate_sbom/     # Main use case + tests
│   │   │   └── check_vulnerabilities.rs
│   │   ├── dto/                   # Data transfer objects
│   │   │   ├── output_format.rs   # OutputFormat enum (Json/Markdown)
│   │   │   ├── sbom_request.rs    # SbomRequest + builder
│   │   │   └── sbom_response.rs   # SbomResponse
│   │   ├── factories/             # Factory pattern implementations
│   │   │   ├── formatter_factory.rs
│   │   │   └── presenter_factory.rs
│   │   └── read_models/           # CQRS read models
│   │       ├── component_view.rs
│   │       ├── dependency_view.rs
│   │       ├── vulnerability_view.rs
│   │       ├── sbom_read_model.rs
│   │       └── sbom_read_model_builder.rs
│   ├── ports/                     # Port interfaces (traits)
│   │   ├── outbound/
│   │   │   ├── lockfile_reader.rs          # LockfileReader trait
│   │   │   ├── project_config_reader.rs    # ProjectConfigReader trait
│   │   │   ├── license_repository.rs       # LicenseRepository trait
│   │   │   ├── vulnerability_repository.rs # VulnerabilityRepository trait
│   │   │   ├── formatter.rs               # SbomFormatter trait
│   │   │   ├── output_presenter.rs        # OutputPresenter trait
│   │   │   ├── progress_reporter.rs       # ProgressReporter trait
│   │   │   └── enriched_package.rs        # EnrichedPackage struct
│   │   └── inbound/               # (reserved for future use)
│   ├── adapters/                  # Infrastructure implementations
│   │   └── outbound/
│   │       ├── filesystem/
│   │       │   ├── file_reader.rs   # FileSystemReader (LockfileReader + ProjectConfigReader)
│   │       │   └── file_writer.rs   # FileSystemWriter, StdoutPresenter
│   │       ├── network/
│   │       │   ├── pypi_client.rs          # PyPiLicenseRepository
│   │       │   ├── caching_pypi_client.rs  # CachingPyPiLicenseRepository
│   │       │   └── osv_client.rs           # OsvClient
│   │       ├── formatters/
│   │       │   ├── cyclonedx_formatter.rs  # CycloneDX JSON output
│   │       │   └── markdown_formatter.rs   # Markdown output
│   │       └── console/
│   │           └── progress_reporter.rs    # StderrProgressReporter
│   └── shared/                    # Shared kernel
│       ├── error.rs               # Domain errors, ExitCode enum
│       ├── result.rs              # Result type alias
│       └── security.rs            # Security validation
├── tests/
│   ├── integration_test.rs        # Use case-level integration tests
│   ├── e2e_test.rs                # Fixture-based E2E tests
│   ├── e2e_vulnerability_threshold.rs  # Vulnerability threshold E2E
│   ├── test_utilities/mocks/      # Mock objects
│   └── fixtures/                  # Test fixtures (sample projects)
│       ├── sample-project/
│       ├── safe_project/
│       ├── vulnerable_project/
│       └── expected-outputs/
├── python-wrapper/                # PyPI distribution wrapper
├── .github/workflows/             # CI/CD (ci.yml, release.yml)
├── .claude/                       # Claude Code config & skills
├── docs/                          # Additional documentation
├── ARCHITECTURE.md                # Architecture details (English)
├── DEVELOPMENT.md                 # Development guide
├── README.md                      # User documentation (English)
└── AGENTS.md                      # This file
```

---

## 3. Architecture Overview

- **Hexagonal Architecture** (Ports & Adapters) + **Domain-Driven Design**
- 5 layers: Domain → Application → Ports → Adapters → Shared Kernel
- **Dependency Injection**: Generic-based static dispatch (zero runtime overhead, compile-time type safety, no `Box<dyn Trait>`)
- `main.rs` handles DI wiring only (no business logic)

> For detailed architecture documentation, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## 4. Key Data Structures & Traits

### Domain Types

- `Package` (name: `PackageName`, version: `Version`, dependencies)
- `LicenseInfo` (license, license_expression, classifiers)
- `DependencyGraph` (aggregate: packages, direct deps, transitive deps map)
- `SbomMetadata` (timestamp, serial_number, tool_version)
- `Vulnerability` (id, summary, severity, cvss_score, affected/fixed versions)
- `Severity` enum: Low, Medium, High, Critical
- `CvssScore` (validated 0.0-10.0)

### Port Traits (outbound)

- `LockfileReader` - Read and parse `uv.lock`
- `ProjectConfigReader` - Read project name from `pyproject.toml`
- `LicenseRepository` - Fetch license info (async)
- `VulnerabilityRepository` - Fetch vulnerability data (async)
- `SbomFormatter` - Format SBOM output
- `OutputPresenter` - Write output (file/stdout)
- `ProgressReporter` - Report progress to user

### Application DTOs

- `SbomRequest` (project_path, format options, CVE options, exclude patterns, ignore_cves)
- `SbomResponse` (enriched packages, metadata, dependency graph, vulnerability results)
- `OutputFormat` enum: Json, Markdown

### Read Models (CQRS)

- `SbomReadModel`, `ComponentView`, `DependencyView`, `VulnerabilityView`

---

## 5. CLI Options

```
uv-sbom [OPTIONS]

  -f, --format <FORMAT>            Output format: json or markdown [default: json]
  -p, --path <PATH>                Project directory path [default: current dir]
  -o, --output <OUTPUT>            Output file path (stdout if omitted)
  -e, --exclude <PATTERN>          Exclude pattern (wildcard * supported, repeatable)
      --dry-run                    Validate config only (skip network/output)
      --check-cve                  Check known vulnerabilities via OSV API (Markdown only)
      --severity-threshold <LEVEL> Severity threshold (low/medium/high/critical, requires --check-cve)
      --cvss-threshold <SCORE>     CVSS score threshold (0.0-10.0, requires --check-cve)
      --verify-links               Verify PyPI links (Markdown only)
  -c, --config <PATH>              Explicit config file path
  -i, --ignore-cve <CVE_ID>       CVE IDs to ignore (repeatable)
  -h, --help                       Show help
  -V, --version                    Show version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Vulnerabilities detected above threshold |
| 2 | Invalid arguments |
| 3 | Application error (missing uv.lock, network error, etc.) |

---

## 6. Configuration System

- **Config file:** `uv-sbom.config.yml` in project root
- **Discovery:** `--config` flag > auto-detect in project directory
- **Priority:** CLI args > config file > defaults
- **List fields** (`exclude_packages`, `ignore_cves`): merged from both sources, deduplicated
- **Validation:** unknown fields warn (ignored), `ignore_cves[].id` must be non-empty

**Example config:**

```yaml
format: markdown
exclude_packages:
  - setuptools
  - pip
  - debug-*
check_cve: true
severity_threshold: HIGH
cvss_threshold: 7.0
ignore_cves:
  - id: CVE-2024-1234
    reason: "Not applicable to our usage"
  - id: CVE-2024-5678
```

---

## 7. Test Structure

- **Test pyramid:** Unit (domain/adapters) → Integration (use cases with mocks) → E2E (fixture-based)

### Test Files

| File | Description |
|------|-------------|
| `tests/integration_test.rs` | Use case-level with mocks |
| `tests/e2e_test.rs` | JSON/Markdown output validation |
| `tests/e2e_vulnerability_threshold.rs` | Vulnerability threshold tests |
| `src/application/use_cases/generate_sbom/tests.rs` | Use case unit tests |
| Per-module `#[cfg(test)] mod tests` blocks | Inline unit tests |

### Mocks (`tests/test_utilities/mocks/`)

- `MockLockfileReader`, `MockProjectConfigReader`, `MockLicenseRepository`, `MockProgressReporter`

### Fixtures (`tests/fixtures/`)

- `sample-project/` - Standard test project
- `safe_project/` - No vulnerabilities
- `vulnerable_project/` - Has vulnerabilities
- `expected-outputs/` - Expected output files

### Run Commands

```bash
cargo test --all           # All tests
cargo test --all --release # Release mode tests
```

---

## 8. CI/CD

### Quality Check Commands (must pass before commit/push)

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

### CI Triggers

Push to: `main`, `develop`, `feature/**`, `bugfix/**`, `fix/**`, `refactor/**`, `doc/**`, `hotfix/**`

### CI Jobs

- **Test:** 3 OS (ubuntu, macos, windows) × stable Rust
- **Clippy:** Lint with `-D warnings`
- **Format:** `cargo fmt --all -- --check`
- **Build:** 3 OS release builds

### Release Flow

Tag `v*` → validate versions → build (4 platforms) → GitHub Release → PyPI publish

> For development workflow details, see [DEVELOPMENT.md](./DEVELOPMENT.md).
