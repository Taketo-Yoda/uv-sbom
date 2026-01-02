# Distribution Guide for uv-sbom

This document provides an overview of all distribution methods for `uv-sbom`.

## Distribution Methods

### 1. Cargo (crates.io) - Rust Ecosystem ✅ ACTIVE

**Status**: Published at https://crates.io/crates/uv-sbom

**Installation**:
```bash
cargo install uv-sbom
```

**Update Process**: Automatic via CI when pushing git tags (`v*`)

**See**: Standard Rust crate publishing

---

### 2. GitHub Releases - Pre-built Binaries ✅ ACTIVE

**Status**: Active at https://github.com/Taketo-Yoda/uv-sbom/releases

**Platforms**:
- macOS (Apple Silicon): `aarch64-apple-darwin`
- macOS (Intel): `x86_64-apple-darwin`
- Linux (x86_64): `x86_64-unknown-linux-gnu`
- Windows (x86_64): `x86_64-pc-windows-msvc`

**Update Process**: Automatic via GitHub Actions on git tag push

**See**: `.github/workflows/release.yml`

---

### 3. Homebrew Tap - macOS/Linux Package Manager ❌ NOT IMPLEMENTED

**Status**: Not planned

Homebrew support is not currently implemented. Users should use one of the other installation methods.

---

### 4. PyPI - Python Package Index 🔜 SETUP REQUIRED

**Status**: Code ready, deployment pending

**Package Name**: `uv-sbom-bin` (wrapper for Rust binary)

**Installation** (after setup):
```bash
uv tool install uv-sbom-bin
# or
pip install uv-sbom-bin
```

**Setup Steps**:

1. **Create PyPI accounts**:
   - Production: https://pypi.org/account/register/
   - Test: https://test.pypi.org/account/register/

2. **(Optional) Create separate repository**:
   ```bash
   # Recommended for cleaner separation
   # Create: https://github.com/Taketo-Yoda/uv-sbom-python

   # Copy wrapper code
   cp -r /path/to/uv-sbom/python-wrapper/* /path/to/uv-sbom-python/
   ```

3. **Configure trusted publishing**:
   - Go to https://pypi.org/manage/account/publishing/
   - Add pending publisher:
     - Project: `uv-sbom-bin`
     - Owner: `Taketo-Yoda`
     - Repo: `uv-sbom-python` (or `uv-sbom` if subdirectory)
     - Workflow: `publish-pypi.yml`
     - Environment: `pypi`

4. **Test locally**:
   ```bash
   cd python-wrapper
   python -m build
   pip install dist/uv_sbom_bin-0.1.0-py3-none-any.whl
   uv-sbom --version
   ```

5. **Publish**:
   ```bash
   # Create and push tag
   git tag py-v0.1.0
   git push origin py-v0.1.0

   # GitHub Actions will publish automatically
   ```

**See**: [docs/PYPI_WRAPPER_SETUP.md](PYPI_WRAPPER_SETUP.md)

---

## Release Workflow

### Standard Release (Rust Binary)

When releasing a new version (e.g., v0.2.0):

1. **Update version** in `Cargo.toml`
2. **Update CHANGELOG.md**
3. **Commit and tag**:
   ```bash
   git add Cargo.toml CHANGELOG.md
   git commit -m "chore: bump version to v0.2.0"
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin main
   git push origin v0.2.0
   ```

4. **Wait for CI** to complete:
   - Builds binaries for all platforms
   - Creates GitHub Release
   - Publishes to crates.io (manual: `cargo publish`)

5. **Update PyPI wrapper** (if published):
   ```bash
   # Update version in python-wrapper/pyproject.toml
   # Update UV_SBOM_VERSION in python-wrapper/uv_sbom_bin/install.py
   # Tag and push: py-v0.2.0
   ```

### Python Wrapper Release Only

If only updating the Python wrapper (no Rust changes):

```bash
# Update version in pyproject.toml
# No need to update UV_SBOM_VERSION if using same binary
git tag py-v0.1.1  # Patch version
git push origin py-v0.1.1
```

---

## Distribution Strategy Summary

| Method | Target Users | Status | Maintenance |
|--------|--------------|--------|-------------|
| **Cargo** | Rust developers | ✅ Active | Automatic |
| **GitHub Releases** | All users | ✅ Active | Automatic |
| **PyPI** | Python developers | 🔜 Ready | Automatic on tag push |

---

## Quick Start Checklist

For **PyPI**:
- [ ] Create PyPI account
- [ ] Configure trusted publishing
- [ ] (Optional) Create separate repository
- [ ] Update versions in pyproject.toml and install.py
- [ ] Tag and push: `py-v0.1.0`
- [ ] Verify: `pip install uv-sbom-bin`

---

## Documentation

- [PyPI Wrapper Setup Guide](PYPI_WRAPPER_SETUP.md)
- [Release Checklist](../RELEASE.md)
