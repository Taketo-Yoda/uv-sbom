# PyPI Wrapper Setup Guide

This guide explains how to set up and maintain the PyPI wrapper for `uv-sbom`.

## Overview

The PyPI wrapper (`uv-sbom-bin`) is a Python package that downloads and installs the prebuilt Rust binary. This allows Python users to install `uv-sbom` via:

```bash
uv tool install uv-sbom-bin
# or
pip install uv-sbom-bin
```

## Repository Setup (Recommended: Separate Repository)

### Option A: Separate Repository (Recommended)

Create a new repository for the Python wrapper:

1. **Create repository**: `https://github.com/Taketo-Yoda/uv-sbom-python`
2. **Copy files** from `python-wrapper/` directory:
   ```bash
   cp -r python-wrapper/* /path/to/uv-sbom-python/
   ```
3. **Initialize git**:
   ```bash
   cd /path/to/uv-sbom-python
   git init
   git add .
   git commit -m "Initial commit: Python wrapper for uv-sbom"
   ```

### Option B: Same Repository (Subdirectory)

Keep the wrapper in the `python-wrapper/` subdirectory of this repository.

**Note**: Option A is recommended for cleaner separation and easier PyPI publishing.

## PyPI Account Setup

### 1. Create PyPI Account

- Production: https://pypi.org/account/register/
- Test: https://test.pypi.org/account/register/

### 2. Configure Trusted Publishing (Recommended)

GitHub Actions can publish directly to PyPI without API tokens:

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new pending publisher:
   - **PyPI Project Name**: `uv-sbom-bin`
   - **Owner**: `Taketo-Yoda`
   - **Repository name**: `uv-sbom-python` (or `uv-sbom` if using subdirectory)
   - **Workflow name**: `publish-pypi.yml`
   - **Environment name**: `pypi`

3. Repeat for TestPyPI: https://test.pypi.org/manage/account/publishing/

### Alternative: API Tokens

If not using trusted publishing:

1. Generate API token at https://pypi.org/manage/account/token/
2. Add as GitHub secret: `PYPI_API_TOKEN`
3. Update workflow to use token authentication

## Directory Structure

```
uv-sbom-python/  (or python-wrapper/)
├── .github/
│   └── workflows/
│       └── publish-pypi.yml
├── uv_sbom_bin/
│   ├── __init__.py
│   ├── __main__.py
│   └── install.py
├── pyproject.toml
└── README.md
```

## Publishing Workflow

### For New Releases

1. **Update version** in `pyproject.toml` and `install.py`:
   ```python
   # pyproject.toml
   version = "0.2.0"

   # install.py
   UV_SBOM_VERSION = "0.2.0"
   ```

2. **Test locally** (optional):
   ```bash
   cd python-wrapper  # or uv-sbom-python repository
   python -m build
   pip install dist/uv_sbom_bin-0.2.0-py3-none-any.whl
   uv-sbom --version
   ```

3. **Commit and tag**:
   ```bash
   git add pyproject.toml uv_sbom_bin/install.py
   git commit -m "Bump version to 0.2.0"
   git tag py-v0.2.0
   git push origin main
   git push origin py-v0.2.0
   ```

4. **GitHub Actions** will automatically:
   - Build the Python package
   - Publish to TestPyPI
   - Publish to PyPI

5. **Verify installation**:
   ```bash
   pip install --upgrade uv-sbom-bin
   uv-sbom --version
   ```

## Manual Publishing

If you need to publish manually:

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# Check the package
twine check dist/*

# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ uv-sbom-bin

# Upload to PyPI
twine upload dist/*
```

## Synchronizing Versions

The Python wrapper version should match the Rust binary version:

| Rust Binary | Python Wrapper | Git Tag |
|-------------|----------------|---------|
| v0.1.0 | 0.1.0 | py-v0.1.0 |
| v0.2.0 | 0.2.0 | py-v0.2.0 |

**Important**: Update `UV_SBOM_VERSION` in `install.py` whenever you release a new Rust binary version.

## Platform Support

The wrapper currently supports:
- macOS (Apple Silicon): `aarch64-apple-darwin`
- macOS (Intel): `x86_64-apple-darwin`
- Linux (x86_64): `x86_64-unknown-linux-gnu`
- Windows (x86_64): `x86_64-pc-windows-msvc`

To add more platforms:
1. Add build target in Rust project's `.github/workflows/release.yml`
2. Update `get_platform_info()` in `install.py`

## Testing

### Local Testing

```bash
# Install in development mode
cd python-wrapper
pip install -e .

# Test the CLI
uv-sbom --version
uv-sbom --help
```

### Testing with Different Python Versions

```bash
# Using tox (create tox.ini)
tox

# Or manually
python3.8 -m pip install .
python3.9 -m pip install .
python3.10 -m pip install .
python3.11 -m pip install .
python3.12 -m pip install .
```

## Troubleshooting

### Binary Download Fails

1. Check GitHub release exists and binaries are uploaded
2. Verify URL in `install.py` matches actual release URL
3. Check SHA256 hash if implemented

### Import Errors

Ensure `__init__.py` exists in `uv_sbom_bin/` directory.

### CLI Not Found

The package uses `[project.scripts]` in `pyproject.toml`. Verify:
```toml
[project.scripts]
uv-sbom = "uv_sbom_bin.__main__:main"
```

### Platform Detection Issues

Test on the target platform:
```bash
python -c "from uv_sbom_bin.install import get_platform_info; print(get_platform_info())"
```

## Maintenance

### Regular Updates

When releasing a new Rust binary version:
1. Update `UV_SBOM_VERSION` in `install.py`
2. Update `version` in `pyproject.toml`
3. Test installation
4. Create tag and push

### Monitoring

- Check PyPI download stats: https://pypistats.org/packages/uv-sbom-bin
- Monitor GitHub Actions for failed publishes
- Review issues on both repositories

## Reference

- [Python Packaging User Guide](https://packaging.python.org/)
- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [Hatchling Build System](https://hatch.pypa.io/latest/)
- [GitHub Actions PyPI Publish](https://github.com/marketplace/actions/pypi-publish)
