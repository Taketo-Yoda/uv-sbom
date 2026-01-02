# uv-sbom-bin

Python wrapper for the `uv-sbom` CLI tool written in Rust.

This package allows Python users to install `uv-sbom` via PyPI and use it with `uv tool install`.

## Installation

### Via pip

```bash
pip install uv-sbom-bin
```

### Via uv

```bash
uv tool install uv-sbom-bin
```

## Usage

After installation, the `uv-sbom` command will be available in your PATH:

```bash
uv-sbom --version
uv-sbom --format json
uv-sbom --format markdown --output SBOM.md
```

## How It Works

This package downloads the prebuilt Rust binary for your platform from the [GitHub releases](https://github.com/Taketo-Yoda/uv-sbom/releases) and installs it.

Supported platforms:
- macOS (Apple Silicon and Intel)
- Linux (x86_64)
- Windows (x86_64)

## Development

This is a wrapper package. The actual tool is developed at:
https://github.com/Taketo-Yoda/uv-sbom

## License

MIT License - see [LICENSE](https://github.com/Taketo-Yoda/uv-sbom/blob/main/LICENSE)
