# yanked-versions-project

An example project demonstrating the `--check-yanked` feature of `uv-sbom` using a Python
package version that has been **yanked on PyPI**.

## Purpose

This project exists because `--check-yanked` queries PyPI for the **yanked status of each
locked version**. Most demonstration projects pin non-yanked versions, so the check would
return "No yanked packages detected."

This project pins `requests==2.32.0`, which was yanked on PyPI due to conflicts with the
CVE-2024-35195 mitigation. Running `--check-yanked` here always produces a non-empty
Yanked Packages section.

> :warning: Do not use this pinned version in production.

## Yanked Packages in This Example

| Package  | Locked Version | Yanked Reason                                              |
|----------|---------------|-------------------------------------------------------------|
| requests | 2.32.0        | Yanked due to conflicts with CVE-2024-35195 mitigation     |

## Prerequisites

- `uv-sbom` built from source (`cargo build --release`) or installed
- Network access (one PyPI API call per package)

## Usage

```bash
# From the repository root
uv-sbom -p examples/yanked-versions-project --check-yanked --no-check-cve -f markdown
```

**Expected Yanked Packages section:**

```markdown
## Yanked Packages

Packages whose locked versions have been yanked from PyPI. Yanked releases typically indicate critical bugs, security issues, or accidental publishes. Update to a non-yanked version.

| Package | Version | Type | Reason | Status |
|---------|---------|------|--------|--------|
| requests | 2.32.0 | Direct dependencies | Yanked due to conflicts with CVE-2024-35195 mitigation | ⚠️ |
```

The process exits with code **1** because a yanked package was detected.
