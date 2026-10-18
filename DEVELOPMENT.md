# Development Guide

## Prerequisites

- Rust 1.70 or later
- Cargo

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

## Running

```bash
# Run with cargo
cargo run -- --help

# Run with specific arguments
cargo run -- --path examples/sample-project --format markdown
```

## Testing

```bash
# Run all tests
cargo test --all

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_parse_lockfile
```

CI additionally runs the test suite in release mode (`cargo test --all --release`).

## Code formatting

```bash
# Check formatting
cargo fmt --all -- --check

# Apply formatting
cargo fmt --all
```

## Linting

```bash
# Run clippy for linting
cargo clippy --all-targets --all-features -- -D warnings
```

`--all-targets` also lints tests, benches, and examples, `--all-features` lints feature-gated code, and `-D warnings` turns warnings into errors, as CI does.

## Pre-push hook

Run `make setup` once after cloning. It enables `.githooks/pre-push`, which runs the CI fmt, clippy, and test checks before every push (CI additionally runs release-mode tests and a release build):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## Project Structure

This project follows **Hexagonal Architecture** (Ports & Adapters) + **Domain-Driven Design** principles.

For detailed architecture information, see:
- [ARCHITECTURE.md](ARCHITECTURE.md) - Complete architecture documentation with layer diagrams and directory structure
- [ARCHITECTURE-JP.md](ARCHITECTURE-JP.md) - Japanese version

## Testing with sample project

```bash
# Generate JSON SBOM for the sample project
cargo run -- --path examples/sample-project --format json

# Generate Markdown SBOM for the sample project
cargo run -- --path examples/sample-project --format markdown

# Save to file
cargo run -- --path examples/sample-project --format json --output examples/sbom.json
```

## Branch Strategy

This project follows a Git Flow-inspired branching strategy:

### Main Branches

- **`main`**: Production-ready code. All releases are tagged here.
- **`develop`**: Integration branch for features. Latest development code.

### Feature Branches

For new features or refactoring:

**Naming convention**: `feature/<issue-number>-<short-description>`

Examples:
- `feature/9-strategy-pattern-formatter`
- `feature/12-add-csv-export`
- `feature/15-improve-error-handling`

**Workflow**:
1. Create branch from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/9-strategy-pattern-formatter
   ```
2. Implement the feature with tests
3. Commit changes with descriptive messages
4. Push to remote and create Pull Request to `develop`
5. After review and approval, merge to `develop`

### Bug Fix Branches

For bug fixes:

**Naming convention**: `bugfix/<issue-number>-<short-description>`

Example: `bugfix/20-fix-license-parsing`

### Hotfix Branches

For urgent production fixes:

**Naming convention**: `hotfix/<issue-number>-<short-description>`

**Workflow**:
1. Branch from `main`
2. Fix the issue
3. Merge to both `main` and `develop`

## Adding new features

1. Create a feature branch following the naming convention above
2. Implement the feature with tests
3. Run `cargo test --all` to ensure all tests pass
4. Run `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` to ensure code quality (these run automatically on push after `make setup`)
5. Update documentation if needed
6. Submit a pull request to `develop`

## Release process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create a git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
4. Push tags: `git push --tags`
5. Build release binaries: `cargo build --release`
