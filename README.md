# uv-sbom

[![GitHub release](https://img.shields.io/github/release/Taketo-Yoda/uv-sbom.svg)](https://github.com/Taketo-Yoda/uv-sbom/releases) [![PyPI - Version](https://img.shields.io/pypi/v/uv-sbom-bin?logo=python&logoColor=white&label=PyPI)](https://pypi.org/project/uv-sbom-bin/) [![Crates.io Version](https://img.shields.io/crates/v/uv-sbom?logo=rust&logoColor=white)](https://crates.io/crates/uv-sbom)
[![shield_license]][license_file] [![CI](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/Taketo-Yoda/uv-sbom/actions/workflows/ci.yml)

[English](README.md) | [日本語](README-JP.md)

----

Generate SBOMs (Software Bill of Materials) for Python projects managed by [uv](https://github.com/astral-sh/uv).

## Features

- 📦 Parses `uv.lock` files to extract dependency information
- 🔍 Automatically fetches license information from PyPI with retry logic
- 📊 Outputs in multiple formats:
  - **CycloneDX 1.6** JSON format (standard SBOM format)
  - **Markdown** format with direct and transitive dependencies clearly separated
- 🚀 Fast and standalone - written in Rust
- 💾 Output to stdout or file
- 🛡️ Robust error handling with helpful error messages and suggestions
- 📈 Progress tracking during license information retrieval
- 🏗️ Built with **Hexagonal Architecture** (Ports and Adapters) + **Domain-Driven Design** for maintainability and testability
- ✅ Comprehensive test coverage (Unit, Integration, E2E)

## Scope and Key Differences from CycloneDX

### SBOM Scope

This tool generates SBOMs based on **uv.lock** file contents, which includes:
- Direct runtime dependencies
- Transitive runtime dependencies
- Development dependencies (if locked in uv.lock)

**What's NOT included:**
- Build system dependencies (e.g., hatchling, setuptools)
- Publishing tools (e.g., twine, build)
- Dependencies only present in the virtual environment but not locked in uv.lock

### Comparison with CycloneDX Official Tools

As of v7.2.1, the official cyclonedx-python library does not yet provide direct support for uv. When generating SBOMs for Python projects:

| Aspect | uv-sbom (this tool) | CycloneDX Official Tools |
|--------|---------------------|--------------------------|
| **Data Source** | `uv.lock` file | `.venv` virtual environment |
| **Scope** | Production runtime dependencies only | Entire supply chain including build/dev tools |
| **Package Count** | Typically fewer (e.g., 16 packages) | Typically more (e.g., 38+ packages) |
| **Use Case** | Production security scanning | Comprehensive supply chain audit |
| **Accuracy** | Reflects locked dependencies | Reflects installed packages |

### Which Tool Should You Use?

- **For production security scanning**: Use `uv-sbom` to focus on dependencies that will be deployed to production
- **For comprehensive supply chain audit**: Use CycloneDX official tools to include all development and build-time dependencies
- **For regulatory compliance**: Check your specific requirements - some regulations may require the comprehensive approach

The focused approach of `uv-sbom` reduces noise in security vulnerability scanning by excluding build-time dependencies that don't ship with the final application.

## Installation

### Cargo (Recommended for Rust users)

![Crates.io Total Downloads](https://img.shields.io/crates/d/uv-sbom)

Install from [crates.io](https://crates.io/crates/uv-sbom):

```bash
cargo install uv-sbom
```

### uv tool (Python users)

![PyPI - Downloads](https://img.shields.io/pypi/dm/uv-sbom-bin?logo=PyPI&logoColor=white)

Install the Python wrapper package:

```bash
uv tool install uv-sbom-bin
```

Or via pip:

```bash
pip install uv-sbom-bin
```

After installation, use the `uv-sbom` command:

```bash
uv-sbom --version
```

**Note**: The package name is `uv-sbom-bin`, but the installed command is `uv-sbom`.

### Pre-built Binaries

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/Taketo-Yoda/uv-sbom/total?logo=GitHub)


Download pre-built binaries from [GitHub Releases](https://github.com/Taketo-Yoda/uv-sbom/releases):

**macOS (Apple Silicon)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-aarch64-apple-darwin.tar.gz
tar xzf uv-sbom-aarch64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**macOS (Intel)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-apple-darwin.tar.gz
tar xzf uv-sbom-x86_64-apple-darwin.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Linux (x86_64)**:
```bash
curl -LO https://github.com/Taketo-Yoda/uv-sbom/releases/latest/download/uv-sbom-x86_64-unknown-linux-gnu.tar.gz
tar xzf uv-sbom-x86_64-unknown-linux-gnu.tar.gz
sudo mv uv-sbom /usr/local/bin/
```

**Windows**:
Download `uv-sbom-x86_64-pc-windows-msvc.zip` from the [releases page](https://github.com/Taketo-Yoda/uv-sbom/releases) and extract to your desired location.

### From Source

```bash
# Clone the repository
git clone https://github.com/Taketo-Yoda/uv-sbom.git
cd uv-sbom

# Build and install
cargo build --release
cargo install --path .
```

### Verify Installation

```bash
uv-sbom --version
```

## Usage

### Basic usage

Generate a CycloneDX JSON SBOM for the current directory:

```bash
uv-sbom
```

### Output formats

Generate a Markdown table with direct and transitive dependencies:

```bash
uv-sbom --format markdown
```

Generate a CycloneDX JSON (default):

```bash
uv-sbom --format json
```

### Specify project path

Analyze a project in a different directory:

```bash
uv-sbom --path /path/to/project
```

### Save to file

Output to a file instead of stdout:

```bash
uv-sbom --format json --output sbom.json
uv-sbom --format markdown --output SBOM.md
```

### Combined options

```bash
uv-sbom --path /path/to/project --format markdown --output SBOM.md
```

### Excluding packages

You can exclude specific packages from the SBOM using the `--exclude` or `-e` option:

```bash
# Exclude a single package
uv-sbom -e "pytest"

# Exclude multiple packages
uv-sbom -e "pytest" -e "mypy" -e "black"

# Use wildcards to exclude patterns
uv-sbom -e "debug-*"        # Exclude all packages starting with "debug-"
uv-sbom -e "*-dev"          # Exclude all packages ending with "-dev"
uv-sbom -e "*-test-*"       # Exclude all packages containing "-test-"

# Combine with other options
uv-sbom --format json --output sbom.json -e "pytest" -e "*-dev"
```

**Pattern Syntax:**
- Use `*` as a wildcard to match zero or more characters
- Patterns are case-sensitive
- Maximum 64 patterns per invocation

**Preventing Information Leakage:**
Use the `--exclude` option to skip specific internal or proprietary libraries. This prevents their names from being sent to external registries (like PyPI) during metadata retrieval, ensuring your internal project structure remains private.

### Validating configuration with dry-run

Use the `--dry-run` option to validate your configuration before the tool communicates with external registries:

```bash
# Verify exclude patterns work correctly
uv-sbom --dry-run -e "internal-*" -e "proprietary-pkg"

# Test configuration with all options
uv-sbom --dry-run --path /path/to/project --format json -e "*-dev"
```

**Why use --dry-run:**
- **Verify exclude patterns**: Ensure your `--exclude` patterns correctly match the packages you want to skip
- **Prevent information leakage**: Confirm that sensitive internal packages are excluded BEFORE the tool communicates with PyPI registry
- **Fast validation**: All input validation happens without network overhead
- **Early error detection**: Catch configuration issues (missing uv.lock, invalid patterns, etc.) immediately

**What happens in dry-run mode:**
- ✅ Reads and parses `uv.lock` file
- ✅ Validates all command-line arguments
- ✅ Checks exclude patterns and warns about unmatched patterns
- ✅ Outputs success message if no issues found
- ❌ Skips license fetching from PyPI (no network communication)
- ❌ Skips SBOM output generation

## Security

### Exclude Pattern Input Validation

The `-e`/`--exclude` option implements the following security measures to protect against malicious input:

#### Character Restrictions

Only the following characters are allowed in patterns:
- **Alphanumeric characters**: a-z, A-Z, 0-9, Unicode letters/numbers
- **Hyphens** (`-`), **underscores** (`_`), **dots** (`.`): Common in package names
- **Square brackets** (`[`, `]`): For package extras (e.g., `requests[security]`)
- **Asterisks** (`*`): For wildcard matching

Control characters, shell metacharacters, and path separators are blocked to prevent:
- Terminal escape sequence injection
- Log injection attacks
- Command injection (defense in depth)

#### Pattern Limits

- **Maximum patterns**: 64 patterns can be specified per invocation
- **Maximum length**: 255 characters per pattern
- **Minimum content**: Patterns must contain at least one non-wildcard character

These limits prevent denial-of-service attacks via:
- Excessive memory consumption
- CPU exhaustion from complex pattern matching

#### Examples

**Valid patterns**:
```bash
uv-sbom -e 'pytest'           # Exact match
uv-sbom -e 'test-*'           # Prefix wildcard
uv-sbom -e '*-dev'            # Suffix wildcard
uv-sbom -e 'package[extra]'   # Package with extras
```

**Invalid patterns** (rejected with error):
```bash
uv-sbom -e ''                 # Empty pattern
uv-sbom -e '***'              # Only wildcards
uv-sbom -e 'pkg;rm -rf /'     # Contains shell metacharacter
uv-sbom -e "$(cat /etc/passwd)" # Shell command substitution blocked
```

For more detailed security information, including threat model and attack vectors, see [SECURITY.md](SECURITY.md).

## Command-line options

```
Options:
  -f, --format <FORMAT>    Output format: json or markdown [default: json]
  -p, --path <PATH>        Path to the project directory [default: current directory]
  -o, --output <OUTPUT>    Output file path (if not specified, outputs to stdout)
  -e, --exclude <PATTERN>  Exclude packages matching patterns (supports wildcards: *)
      --dry-run            Validate configuration without network communication or output generation
  -h, --help               Print help
  -V, --version            Print version
```

## Output Examples

### Markdown format

> **Note**: The Markdown format sample is based on the SBOM format from [ja-complete v0.1.0](https://github.com/Taketo-Yoda/ja-complete/tree/v0.1.0).

```markdown
# Software Bill of Materials (SBOM)

## Component Inventory

A comprehensive list of all software components and libraries included in this project.

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |
| ...additional packages... |

## Direct Dependencies

Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| janome | 0.5.0 | AL2 | Japanese morphological analysis engine. |
| pydantic | 2.12.5 | MIT | Data validation using Python type hints |

## Transitive Dependencies

Secondary dependencies introduced by the primary packages.

### Dependencies for pydantic

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| annotated-types | 0.7.0 | MIT License | Reusable constraint types to use with typing.Annotated |
| pydantic-core | 2.41.5 | MIT | Core functionality for Pydantic validation and serialization |
```

### CycloneDX JSON format

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:...",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "tools": [
      {
        "name": "uv-sbom",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "description": "HTTP library for Python",
      "licenses": [
        {
          "license": {
            "name": "Apache 2.0"
          }
        }
      ],
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```

## Requirements

- A Python project managed by `uv` with a `uv.lock` file
- Internet connection for fetching license information from PyPI

## Error Handling

uv-sbom provides detailed error messages with helpful suggestions:

- **Missing uv.lock file**: Clear message with suggestions on how to fix
- **Invalid project path**: Validates directory existence before processing
- **License fetch failures**: Retries failed requests (up to 3 attempts) and continues processing
- **File write errors**: Checks directory existence and permissions
- **Progress tracking**: Shows real-time progress during license information retrieval

Example error message:
```
❌ An error occurred:

uv.lock file not found: /path/to/project/uv.lock

💡 Hint: uv.lock file does not exist in project directory "/path/to/project".
   Please run in the root directory of a uv project, or specify the correct path with the --path option.
```

## Troubleshooting

### uv.lock file not found
Ensure you're running the command in a directory containing a `uv.lock` file, or use the `--path` option to specify the correct project directory.

### License information fetch failures
Some packages may fail to retrieve license information from PyPI. The tool will:
1. Automatically retry up to 3 times
2. Continue processing other packages
3. Display warnings for failed packages
4. Include packages in the output without license information if fetching fails

### Network issues
If you're behind a proxy or firewall, ensure that you can access `https://pypi.org`. The tool uses a 10-second timeout for API requests.

## Documentation

### For Users
- [README.md](README.md) - User documentation
- [LICENSE](LICENSE) - MIT License

### For Developers
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - **Hexagonal Architecture + DDD implementation** (layers, ports, adapters, test strategy, ADRs)
- [CHANGELOG.md](CHANGELOG.md) - Change history

### For Claude Code Users
- [.claude/project-context.md](.claude/project-context.md) - Complete project context for Claude Code
- [.claude/instructions.md](.claude/instructions.md) - Coding guidelines and instructions for Claude Code

These files provide comprehensive context for AI-assisted development with Claude Code.

## License

MIT License - see [LICENSE](LICENSE) file for details.

[shield_license]: https://img.shields.io/badge/license-MIT-blue.svg
[license_file]: LICENSE
