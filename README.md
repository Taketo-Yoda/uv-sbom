# uv-sbom

Generate SBOMs (Software Bill of Materials) for Python projects managed by [uv](https://github.com/astral-sh/uv).

## Features

- 📦 Parses `uv.lock` files to extract dependency information
- 🔍 Automatically fetches license information from PyPI with retry logic
- 📊 Outputs in multiple formats:
  - **CycloneDX 1.6** JSON format (standard SBOM format)
  - **Markdown** table format with package details
- 🚀 Fast and standalone - written in Rust
- 💾 Output to stdout or file
- 🛡️ Robust error handling with helpful error messages and suggestions
- 📈 Progress tracking during license information retrieval

## Installation

### From source

```bash
# Clone the repository
git clone https://github.com/yourusername/uv-sbom.git
cd uv-sbom

# Build and install
cargo build --release
cargo install --path .
```

## Usage

### Basic usage

Generate a CycloneDX JSON SBOM for the current directory:

```bash
uv-sbom
```

### Output formats

Generate a Markdown table:

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

## Command-line options

```
Options:
  -f, --format <FORMAT>  Output format: json or markdown [default: json]
  -p, --path <PATH>      Path to the project directory [default: current directory]
  -o, --output <OUTPUT>  Output file path (if not specified, outputs to stdout)
  -h, --help             Print help
  -V, --version          Print version
```

## Output Examples

### Markdown format

```markdown
# Software Bill of Materials (SBOM)

| Package | Version | License | Description |
|---------|---------|---------|-------------|
| requests | 2.31.0 | Apache 2.0 | HTTP library for Python |
| numpy | 1.24.0 | BSD License | Fundamental package for array computing |
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
- [README.md](README.md) - This file, user documentation
- [LICENSE](LICENSE) - MIT License

### For Developers
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Architecture documentation
- [CHANGELOG.md](CHANGELOG.md) - Change history

### For Claude Code Users
- [.claude/project-context.md](.claude/project-context.md) - Complete project context for Claude Code
- [.claude/instructions.md](.claude/instructions.md) - Coding guidelines and instructions for Claude Code

These files provide comprehensive context for AI-assisted development with Claude Code.

## License

MIT License - see [LICENSE](LICENSE) file for details.
