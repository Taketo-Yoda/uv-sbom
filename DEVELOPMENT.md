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
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_parse_lockfile
```

## Code formatting

```bash
# Check formatting
cargo fmt -- --check

# Apply formatting
cargo fmt
```

## Linting

```bash
# Run clippy for linting
cargo clippy -- -D warnings
```

## Project Structure

```
uv-sbom/
├── Cargo.toml           # Project configuration and dependencies
├── src/
│   ├── main.rs          # Entry point and main logic
│   ├── cli.rs           # CLI argument parsing
│   ├── lockfile.rs      # uv.lock file parser
│   ├── license.rs       # License information fetching
│   ├── cyclonedx.rs     # CycloneDX JSON generation
│   ├── markdown.rs      # Markdown table generation
│   └── error.rs         # Error types
└── examples/
    └── sample-project/  # Sample project for testing
        ├── uv.lock
        └── pyproject.toml
```

## Testing with sample project

```bash
# Generate JSON SBOM for the sample project
cargo run -- --path examples/sample-project --format json

# Generate Markdown SBOM for the sample project
cargo run -- --path examples/sample-project --format markdown

# Save to file
cargo run -- --path examples/sample-project --format json --output examples/sbom.json
```

## Adding new features

1. Create a new branch for your feature
2. Implement the feature with tests
3. Run `cargo test` to ensure all tests pass
4. Run `cargo fmt` and `cargo clippy` to ensure code quality
5. Update documentation if needed
6. Submit a pull request

## Release process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create a git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
4. Push tags: `git push --tags`
5. Build release binaries: `cargo build --release`
