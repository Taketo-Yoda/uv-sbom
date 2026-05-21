# abandoned-packages-project

An example project demonstrating the `--check-abandoned` feature of `uv-sbom` using Python
packages whose **latest release on PyPI** is more than 2 years old.

## Purpose

This project exists because `--check-abandoned` queries PyPI for the **latest release date
of each package** (not the locked version's date). Most demonstration projects pin *old
versions* of actively maintained packages — but those packages have recent latest releases
and are therefore **not** flagged as abandoned.

This project uses packages that are genuinely unmaintained at the PyPI level: even the
most recent version of each package is years old. Running `--check-abandoned` here always
produces a non-empty Abandoned Packages section regardless of the threshold.

> ⚠️ Do not use these packages in production.

## Abandoned Packages in This Example

| Package | Locked Version | Latest PyPI Release | Days Inactive (approx.) | Notes |
|---------|---------------|--------------------|-----------------------|-------|
| docopt  | 0.6.2         | 2014-06-16         | 4400+                 | Succeeded by `docopt-ng` |
| nose    | 1.3.7         | 2015-06-02         | 3990+                 | Officially deprecated; use pytest |
| pep8    | 1.7.1         | 2017-10-24         | 3100+                 | Renamed to `pycodestyle` |
| Paver   | 1.3.4         | 2017-12-31         | 3050+                 | No active maintainer |

`six` (a transitive dependency of Paver) is actively maintained and will **not** appear
in the Abandoned Packages section.

## Prerequisites

- `uv-sbom` built from source (`cargo build --release`) or installed
- Network access (one PyPI API call per package)

## Usage

### Step 1: Abandoned package check (default threshold: 730 days)

```bash
# From the repository root
uv-sbom -p examples/abandoned-packages-project --check-abandoned -f markdown
```

**Expected Abandoned Packages section:**

```markdown
## Abandoned Packages

Packages whose most recent upstream release exceeds the configured inactivity threshold.
Inactive projects may carry unpatched vulnerabilities and pose long-term maintenance risk.

| Package | Version | Last Release | Days Inactive | Type                |
|---------|---------|--------------|---------------|---------------------|
| docopt  | 0.6.2   | 2014-06-16   | 4346          | Direct dependencies |
| nose    | 1.3.7   | 2015-06-02   | 3995          | Direct dependencies |
| pep8    | 1.7.1   | 2017-10-24   | 3120          | Direct dependencies |
| paver   | 1.3.4   | 2017-12-31   | 3052          | Direct dependencies |
```

### Step 2: Custom inactivity threshold

```bash
uv-sbom -p examples/abandoned-packages-project --check-abandoned \
  --abandoned-threshold-days 365 -f markdown
```

All 4 packages still appear (their last releases are 3000+ days ago).

### Step 3: Combined with CVE check

```bash
uv-sbom -p examples/abandoned-packages-project --check-cve --check-abandoned -f markdown
```

## Why Not Just Use `sample-project`?

`examples/sample-project/` pins **old versions** of actively maintained packages
(chardet 3.0.4, idna 2.10, etc.). Those packages have recent latest releases, so
`--check-abandoned` returns 0 abandoned packages when run against `sample-project`.

This project uses packages whose **latest** release is old, so the abandoned check
always flags them.

## Contrast with Other Examples

| | `examples/abandoned-packages-project` | `examples/sample-project` | `examples/suggest-fix-project` | `examples/workspace` |
|---|---|---|---|---|
| Primary feature | `--check-abandoned` (focused) | CVE + license + abandoned | `--suggest-fix` Upgrade Advisor | `--workspace` mode |
| Abandoned demo | ✅ Yes (4 packages, always flagged) | Partial (depends on PyPI state) | ❌ Not focused | ❌ Not focused |
| Vulnerable packages | None | Direct dependencies | Transitive dependencies | N/A |
| Config file | ❌ No | ✅ Yes (`config/`) | ❌ No | ❌ No |
