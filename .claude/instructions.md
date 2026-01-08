# Instructions for Claude Code

This file contains specific instructions for Claude Code when working with this project.

## Project Nature

This project is a **Rust-based CLI tool** that adopts **Hexagonal Architecture + DDD**:

- Language: Rust (Edition 2021)
- Build System: Cargo
- Architecture: Hexagonal (Ports & Adapters)
- Error Handling: anyhow-based with custom error types
- Dependency Injection: Generic-based (static dispatch)

## Understanding the Architecture

### Layer Responsibilities

1. **Domain Layer** (`sbom_generation/`)
   - Pure business logic
   - I/O operations strictly prohibited
   - No use of `std::fs`, `reqwest`, etc.
   - All implemented as pure functions

2. **Application Layer** (`application/`)
   - Use case orchestration
   - Communication with infrastructure through ports
   - Business flow control

3. **Ports Layer** (`ports/`)
   - Interface definitions only
   - Implemented as traits
   - No implementations

4. **Adapters Layer** (`adapters/`)
   - Concrete infrastructure implementations
   - Implements ports
   - Executes I/O operations

5. **Shared Layer** (`shared/`)
   - Error types
   - Type aliases
   - Security validation functions

### Dependency Rules

**CRITICAL**: Strictly adhere to dependency direction

```
Adapters → Application → Domain
    ↓           ↓
  Ports   ←   Ports
```

- Domain layer depends on no other layers
- Application layer depends only on Domain and Ports layers
- Adapters layer implements Ports

## Code Modification Guidelines

### 1. Prohibit Layer Violations

```rust
// ❌ Bad: I/O operations in domain layer
// Inside domain/package.rs
use std::fs;  // NOT ALLOWED!!

// ✅ Good: Via ports
// Inside application/use_cases/generate_sbom.rs
fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
    // I/O operations via ports
    let content = self.lockfile_reader.read_lockfile(&path)?;
}
```

### 2. Error Handling

Provide user-friendly messages:

```rust
// ❌ Bad
return Err(anyhow::anyhow!("Failed"));

// ✅ Good
return Err(SbomError::LockfileParseError {
    path: lockfile_path.clone(),
    details: e.to_string(),
}.into());
```

### 3. Security Validation

Always use functions from `shared/security.rs` for file operations:

```rust
// ✅ Good
use crate::shared::security::{validate_regular_file, validate_file_size};

validate_regular_file(path, "uv.lock")?;
validate_file_size(file_size, path, MAX_FILE_SIZE)?;
```

### 4. Type Aliases

Use type aliases for complex types (to avoid Clippy warnings):

```rust
// ✅ Good
pub type PyPiMetadata = (Option<String>, Option<String>, Vec<String>, Option<String>);

fn fetch_license_info(&self, name: &str, version: &str) -> Result<PyPiMetadata>;
```

### 5. Adding Tests

Add tests for all new features:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_feature() {
        // Domain layer: test pure functions
        // Application layer: use mocks
        // Adapters layer: test with real environment using tempfile, etc.
    }
}
```

## Module-Specific Guidelines

### sbom_generation/domain/

**Responsibility**: Core business logic
**Prohibited**:
- I/O operations (file, network, database)
- External crate dependencies (only `std` allowed)
- Operations with side effects

**Allowed**:
- Value object definitions
- Domain services (pure functions)
- Business policies

### sbom_generation/services/

**Responsibility**: Domain services
**Characteristics**:
- All pure functions
- No I/O dependencies
- Easy to test

**Example**:
```rust
pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    pub fn analyze(
        project_name: &PackageName,
        dependency_map: &HashMap<String, Vec<String>>,
    ) -> Result<DependencyGraph> {
        // Pure algorithm
    }
}
```

### application/use_cases/

**Responsibility**: Workflow orchestration
**Pattern**: Generic-based DI

```rust
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
}

impl<LR, PCR, LREPO, PR> GenerateSbomUseCase<LR, PCR, LREPO, PR>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository,
    PR: ProgressReporter,
{
    pub fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
        // Orchestration
    }
}
```

### ports/outbound/

**Responsibility**: Interface definitions
**Pattern**: Trait definitions

```rust
pub trait LockfileReader {
    fn read_lockfile(&self, project_path: &Path) -> Result<String>;
}
```

### adapters/outbound/

**Responsibility**: Concrete port implementations
**Required**: Security checks

**File System Adapter**:
```rust
impl LockfileReader for FileSystemReader {
    fn read_lockfile(&self, project_path: &Path) -> Result<String> {
        // Security validation
        validate_regular_file(&lockfile_path, "uv.lock")?;

        // Implementation
        self.safe_read_file(&lockfile_path, "uv.lock")
    }
}
```

### shared/

**Responsibility**: Common functionality
**Contents**:
- `error.rs`: Error type definitions
- `result.rs`: Type aliases
- `security.rs`: Security validation functions

## Security Guidelines

### File Operation Security

**Required Checks** (use `shared/security.rs`):
1. Symlink validation - `validate_not_symlink()`
2. Regular file validation - `validate_regular_file()`
3. File size limit - `validate_file_size()`

**Threats to Mitigate**:
- Arbitrary file read (via symlinks)
- DoS attacks (huge files)
- TOCTOU attacks (time-of-check-time-of-use)
- Path traversal

### Network Operation Security

**Required Implementation**:
1. Timeout settings
2. Retry limits
3. Rate limiting (DoS prevention)
4. HTTPS communication

**Example** (PyPiLicenseRepository):
```rust
const MAX_RETRIES: u32 = 3;
const TIMEOUT_SECONDS: u64 = 10;
const RATE_LIMIT_MS: u64 = 100;  // 10 req/sec
```

## Coding Style

### Naming Conventions
- Function names: `snake_case`
- Type names: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Traits: `PascalCase` (verbs preferred)

### Comments
- Public APIs: `///` documentation comments required
- Complex logic: `//` explanatory comments
- Security-related: `// Security:` prefix

### Error Handling
- Use `?` operator extensively
- Avoid `unwrap()` and `expect()` (except in tests)
- Add error context

## Testing Strategy

### Domain Layer Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_logic() {
        // Pure functions, no mocks needed
        let result = DependencyAnalyzer::analyze(...);
        assert_eq!(result, expected);
    }
}
```

### Application Layer Tests
```rust
#[test]
fn test_use_case() {
    // Use mocks
    let mock_reader = MockLockfileReader { ... };
    let use_case = GenerateSbomUseCase::new(mock_reader, ...);

    let result = use_case.execute(request);
    assert!(result.is_ok());
}
```

### Adapters Layer Tests
```rust
#[test]
fn test_file_reader() {
    // Test with real environment using tempfile
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("uv.lock");
    fs::write(&file_path, "content").unwrap();

    let reader = FileSystemReader::new();
    let result = reader.read_lockfile(temp_dir.path());
    assert!(result.is_ok());
}
```

## Performance Considerations

### Bottlenecks
1. PyPI API calls (rate limited)
2. Network latency

### Optimization Notes
- Always perform benchmarking
- Base on profiling results
- Avoid premature optimization

## Documentation Updates

Files to update when adding new features:
1. `README.md` - User guide
2. `.claude/project-context.md` - Architecture information
3. Documentation comments in code
4. Test cases

## Adding Dependencies

When adding new dependencies:

1. **Consider necessity**: Check if existing tools can solve the problem
2. **Minimal features**: Use only required `features`
3. **Appropriate layer**:
   - Domain layer: `std` only
   - Application layer: anyhow, basic utilities
   - Adapters layer: I/O libraries allowed
4. **Update documentation**: Update `.claude/project-context.md`

## Frequently Asked Questions

### Q: What should I do when I find duplicate code or complex conditional branches?
A: Consider applying GoF design patterns:
1. **When duplicate code exists in multiple places**:
   - Template Method pattern: Extract common algorithms
   - Strategy pattern: When algorithm switching is needed (e.g., Formatter selection in Issue #9)
2. **When complex conditional branches (match/if-else) exist**:
   - Strategy pattern: Switch behaviors
   - Factory pattern: Switch object creation
   - Polymorphism: Dynamic dispatch via traits
3. **Always open a GitHub Issue to discuss the design before implementation**

### Q: How do I add a new format?
A:
1. Check the `SbomFormatter` trait in `ports/outbound/formatter.rs`
2. Implement new formatter in `adapters/outbound/formatters/`
3. Add new format type to `OutputFormat` enum in `application/dto/output_format.rs`
4. Update `FormatterFactory::create()` method in `application/factories/formatter_factory.rs`
5. Update `FormatterFactory::progress_message()` (if needed)
6. Add tests (FromStr test for OutputFormat and FormatterFactory tests)

### Q: How do I add a new license source?
A:
1. Implement `LicenseRepository` trait
2. Create new adapter in `adapters/outbound/`
3. Wire DI in `main.rs`
4. Add tests

### Q: Can I call external APIs in the domain layer?
A: **NO!** Define a port and implement it in an adapter

### Q: What if I need file I/O in tests?
A: Use the `tempfile` crate to create temporary files

### Q: What if I forgot security checks for file operations?
A: **Must fix immediately**:
1. Use validation functions from `shared/security.rs`
2. Check symlinks, file size, and regular files
3. Verify security violation cases in tests

## Git/Branch Strategy

This project adopts a Git Flow-based branching strategy (see `DEVELOPMENT.md` for details).

### Check Branch Before Working

**CRITICAL**: Always verify the current branch before starting to code:

```bash
git status
git branch --show-current
```

### Branch Rules

1. **Do not work directly on the `develop` branch**
   - Always create a feature branch first

2. **Never work on the `main` branch**
   - main is for production releases only

3. **Proper branch naming conventions**:
   - Feature: `feature/<issue-number>-<short-description>`
   - Bugfix: `bugfix/<issue-number>-<short-description>`
   - Hotfix: `hotfix/<issue-number>-<short-description>`
   - Documentation: `docs/<issue-number>-<short-description>`

### Checklist When Starting Work

```bash
# 1. Check current branch
git branch --show-current

# 2. If on develop or main branch, create a feature branch
git checkout develop
git pull origin develop
git checkout -b feature/<issue-number>-<description>

# 3. Start working
```

### Pre-Commit Verification

Before committing all changes:

1. **Verify you're on the correct branch**
   ```bash
   git branch --show-current
   # Ensure it's feature/*, bugfix/*, or hotfix/*
   ```

2. **Review changes**
   ```bash
   git status
   git diff
   ```

3. **Run quality checks** (described below)

## Claude Code Workflow

### When Starting Work

1. **Check branch (required)**: Verify current branch with `git status`
   - If on `develop` or `main` → Create a feature branch
   - If on a feature branch → Continue work
2. **Check context**: Read `.claude/project-context.md`
3. **Verify architecture**: Understand layer responsibilities

### During Coding

4. **Identify changes**: Make changes in the appropriate layer
5. **Consider design patterns**: Before implementation, consider applying GoF design patterns
   - For duplicate code or complex conditionals, consider appropriate patterns (Strategy, Factory, Template Method, etc.)
   - Verify consistency with existing architecture patterns (Hexagonal, DDD)
6. **Security review**: During implementation, verify:
   - File operations: Use validation functions from `shared/security.rs`
   - Network operations: Implement timeouts, retries, rate limiting
   - Input validation: Properly validate user input and external data
   - Error messages: Do not include sensitive information (paths, internal structures, etc.)
7. **Add tests**: Always add tests for new features
8. **Verify build**: `cargo build`
9. **Run tests**: `cargo test`
10. **Quality checks (required)**:
    - **Format check**: `cargo fmt --all -- --check` (if errors, fix with `cargo fmt --all`)
    - **Clippy check**: `cargo clippy --all-targets --all-features -- -D warnings` (zero warnings required)

### When Completing Work

11. **Update documentation**: As needed
12. **Check branch**: Verify branch again before committing
13. **Commit**: Commit changes with appropriate commit message

**Important**:
- Step 1 branch check is **mandatory at the start of work**
- Step 5 design pattern consideration is **mandatory before implementation**
- Step 6 security review is **continuously performed during implementation**
- Step 10 quality checks are **mandatory upon coding completion**
- Code is not considered complete unless all these checks pass

## Important Notes

### Prohibit Breaking Changes
- Be careful with public API changes
- Do not delete or modify existing CLI options
- Maintain backward compatibility

### Code Quality

**Required checks upon coding completion**:
1. **Design pattern verification**:
   - Verify GoF patterns are applied to duplicate code or complex conditionals
   - Consider applicability of Strategy, Factory, Template Method, Builder, etc.
   - Verify consistency with existing architecture (Hexagonal, DDD)
2. **Security verification**:
   - File operations: Verify use of validation functions from `shared/security.rs`
   - Network operations: Verify implementation of timeouts, retries, rate limiting
   - Input validation: Verify validation of user input and external data
   - Error messages: Verify no sensitive information leakage
   - Consider OWASP Top 10 vulnerabilities (path traversal, injection, etc.)
3. **Format**: `cargo fmt --all -- --check` must pass
4. **Clippy**: `cargo clippy --all-targets --all-features -- -D warnings` must have zero warnings
5. **Tests**: `cargo test` must pass all tests
6. **Test coverage**: Always add tests for new features
7. **Documentation**: Always add documentation comments to public APIs

Code is not complete unless all these checks pass.

### Security
- File operations: Always use `shared/security.rs`
- Network operations: Configure timeouts and retries
- Error messages: Do not include sensitive information

---

Last Updated: 2025-01-04

## Change History

- 2025-01-04: Added Git/Branch Strategy section
- 2025-01-04: Added design pattern consideration and security review to workflow
