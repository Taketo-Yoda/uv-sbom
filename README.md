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

As of 2026-01-01, the official CycloneDX tools do not yet support uv directly. When generating SBOMs for Python projects:

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

Install from [crates.io](https://crates.io/crates/uv-sbom):

```bash
cargo install uv-sbom
```

### uv tool (Python users)

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

## Command-line options

```
Options:
  -f, --format <FORMAT>    Output format: json or markdown [default: json]
  -p, --path <PATH>        Path to the project directory [default: current directory]
  -o, --output <OUTPUT>    Output file path (if not specified, outputs to stdout)
  -e, --exclude <PATTERN>  Exclude packages matching patterns (supports wildcards: *)
  -h, --help               Print help
  -V, --version            Print version
```

## Exit Codes

uv-sbom returns the following exit codes:

| Exit Code | Description | Examples |
|-----------|-------------|----------|
| 0 | Success | SBOM generated successfully, `--help` or `--version` displayed |
| 1 | Application error | Missing uv.lock file, invalid project path, invalid exclude pattern, network error, file write error |
| 2 | Invalid command-line arguments | Unknown option, invalid argument type |

### Common Error Scenarios

**Exit code 1 - Application errors:**
```bash
# Missing uv.lock file
$ uv-sbom --path /path/without/uv-lock
❌ An error occurred:
uv.lock file not found: /path/without/uv-lock/uv.lock
# Exit code: 1

# Invalid exclude pattern (empty)
$ uv-sbom -e ""
❌ An error occurred:
Exclusion pattern cannot be empty
# Exit code: 1

# Invalid exclude pattern (invalid characters)
$ uv-sbom -e "pkg;name"
❌ An error occurred:
Exclusion pattern contains invalid character ';' in pattern 'pkg;name'
# Exit code: 1

# Nonexistent project path
$ uv-sbom --path /nonexistent
❌ An error occurred:
Invalid project path: /nonexistent
# Exit code: 1
```

**Exit code 2 - CLI argument errors:**
```bash
# Unknown option
$ uv-sbom --unknown-option
error: unexpected argument '--unknown-option' found
# Exit code: 2

# Invalid format value
$ uv-sbom --format invalid
error: invalid value 'invalid' for '--format <FORMAT>'
# Exit code: 2
```

### Usage in Scripts

```bash
#!/bin/bash

uv-sbom --format json --output sbom.json

case $? in
  0)
    echo "SBOM generated successfully"
    ;;
  1)
    echo "Application error occurred"
    exit 1
    ;;
  2)
    echo "Invalid command-line arguments"
    exit 2
    ;;
esac
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

## Network Requirements

### External Domains Accessed

`uv-sbom` makes HTTP requests to the following external services during SBOM generation:

#### Required for all operations:

1. **PyPI (Python Package Index)**
   - Domain: `https://pypi.org`
   - Purpose: Fetch license information for Python packages
   - When: Every SBOM generation (unless using `--dry-run`)
   - Rate limit: No official limit, but tool implements retry logic
   - Endpoint: `/pypi/{package_name}/json`

#### Optional (only when using `--check-cve`):

2. **OSV (Open Source Vulnerability Database)**
   - Domain: `https://api.osv.dev`
   - Purpose: Fetch vulnerability information for security scanning
   - When: Only when `--check-cve` flag is used
   - Rate limit: Tool implements 10 requests/second limit
   - Endpoints:
     - `/v1/querybatch` - Batch query for vulnerability IDs
     - `/v1/vulns/{vuln_id}` - Detailed vulnerability information

### Firewall Configuration

If you are behind a corporate firewall or proxy, ensure the following domains are on the allowlist:

```
# Required
pypi.org

# Optional (only for --check-cve)
api.osv.dev
```

### Proxy Configuration

The tool respects standard HTTP/HTTPS proxy environment variables:

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

uv-sbom --format json
```

### Offline Mode

To validate configuration without making network requests, use `--dry-run`:

```bash
uv-sbom --dry-run
```

This mode:
- Validates `uv.lock` file
- Validates command-line arguments
- Checks exclude patterns
- Skips license fetching (no PyPI access)
- Skips vulnerability checking (no OSV access)
- Skips SBOM output generation

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
