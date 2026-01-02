# Release Checklist for uv-sbom

This document outlines the steps to release a new version of uv-sbom.

## Pre-release Checklist

### 1. Code Quality Verification

```bash
# Run all tests
cargo test --all

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check

# Build release binary
cargo build --release

# Verify binary works
./target/release/uv-sbom --version
./target/release/uv-sbom --help
```

### 2. Update Version Numbers

Update version in the following files:
- [ ] `Cargo.toml` - Update `version` field
- [ ] `CHANGELOG.md` - Move items from `[Unreleased]` to new version section
- [ ] `README.md` - Update version numbers in installation examples (if showing specific version)

### 3. Update CHANGELOG.md

1. Move items from `[Unreleased]` section to new version section with date
2. Add comparison link at bottom of file:
   ```markdown
   [0.2.0]: https://github.com/Taketo-Yoda/uv-sbom/compare/v0.1.0...v0.2.0
   [0.1.0]: https://github.com/Taketo-Yoda/uv-sbom/releases/tag/v0.1.0
   ```

### 4. Commit and Tag

```bash
# Commit version bump
git add Cargo.toml CHANGELOG.md README.md
git commit -m "chore: bump version to v0.x.0"

# Create and push tag
git tag -a v0.x.0 -m "Release v0.x.0"
git push origin main
git push origin v0.x.0
```

## Release Process

### 5. GitHub Actions Automatic Build

After pushing the tag, GitHub Actions will automatically:
1. Build binaries for all supported platforms
2. Create a GitHub Release
3. Upload binary artifacts

**Monitor the workflow**: https://github.com/Taketo-Yoda/uv-sbom/actions

### 6. Publish to crates.io

```bash
# Dry run first
cargo publish --dry-run

# Actual publish
cargo publish
```

**Note**: You need to login first with `cargo login` if you haven't already.

### 7. Verify Release

- [ ] Check GitHub Release page: https://github.com/Taketo-Yoda/uv-sbom/releases
- [ ] Download and test each platform's binary
- [ ] Verify crates.io page: https://crates.io/crates/uv-sbom
- [ ] Test installation from crates.io: `cargo install uv-sbom`

## Post-release Tasks

### 8. Announcements (Optional)

- [ ] Update project homepage if exists
- [ ] Post on Reddit (r/rust, r/python)
- [ ] Tweet about the release
- [ ] Update documentation sites

### 9. Prepare for Next Development Cycle

```bash
# Create [Unreleased] section in CHANGELOG.md
```

## Troubleshooting

### GitHub Actions Build Fails

1. Check the Actions logs: https://github.com/Taketo-Yoda/uv-sbom/actions
2. Fix the issue in the code
3. Delete the tag: `git tag -d v0.x.0 && git push origin :refs/tags/v0.x.0`
4. Fix and re-tag

### crates.io Publish Fails

Common issues:
- Missing required fields in `Cargo.toml` (description, license, etc.)
- Package size too large (check `exclude` in `Cargo.toml`)
- Existing version already published (can't republish the same version)

### Binary Download Issues

If users report download issues:
1. Verify all artifacts uploaded correctly in GitHub Release
2. Check file permissions
3. Verify SHA256 checksums match

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.x.x): Breaking changes
- **MINOR** (x.1.x): New features, backward compatible
- **PATCH** (x.x.1): Bug fixes, backward compatible

## Release Schedule

- Patch releases: As needed for critical bugs
- Minor releases: When new features are ready
- Major releases: When breaking changes are necessary

---

Last updated: 2025-01-02
