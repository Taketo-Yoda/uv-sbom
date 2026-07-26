# sample-project

An example project demonstrating CVE detection, license compliance checking,
and abandoned package detection with `uv-sbom`.

## Purpose

This project contains **intentionally outdated package versions** to produce
realistic uv-sbom output for all three major opt-in analysis features:

| Feature | CLI flag | What this example shows |
|---------|----------|------------------------|
| CVE detection | `--check-cve` (default on) | Multiple known vulnerabilities in locked packages |
| License compliance | `--check-license` | `chardet 3.0.4` uses LGPL-2.1-only (denied) |
| Abandoned package detection | `--check-abandoned` | Some packages may be flagged depending on PyPI state; see `examples/abandoned-packages-project/` for a focused demo |
| Python version compatibility | `--target-python` | Several transitive dependencies declare `Requires-Python` constraints incompatible with older Python versions (e.g. 3.8) |

> ⚠️ **Do not use these package versions in production.** They are intentionally
> outdated for demonstration purposes.

## Prerequisites

- `uv-sbom` installed or built from source (`cargo build --release`)
- Internet access (CVE, license, and abandoned checks all require network)

## Usage

### Step 1: CVE check (default)

```bash
# From the repository root
uv-sbom -p examples/sample-project -f markdown
```

**What you will see:** A vulnerability report listing CVEs for `pillow`, `urllib3`,
`requests`, `jinja2`, and `werkzeug`.

### Step 2: License compliance check

```bash
uv-sbom -p examples/sample-project --check-license -f markdown \
  -c examples/sample-project/config/uv-sbom.config.yml
```

**What you will see:** A License Compliance section flagging `chardet 3.0.4`
(LGPL-2.1-only, denied by the config policy).

### Step 3: Abandoned package detection

```bash
uv-sbom -p examples/sample-project --check-abandoned -f markdown
```

**What you will see:** An Abandoned Packages section listing packages whose
**latest PyPI release** is more than 730 days old (the default threshold).

To lower the threshold and see more results:

```bash
uv-sbom -p examples/sample-project --check-abandoned \
  --abandoned-threshold-days 365 -f markdown
```

### Step 4: Python version compatibility check

```bash
uv-sbom -p examples/sample-project --target-python 3.8 --no-check-cve -f markdown
```

**What you will see:** a progress summary printed to stderr (no Markdown
section is rendered yet — tracked separately in
[#689](https://github.com/Taketo-Yoda/uv-sbom/issues/689)):

```text
🔍 Checking Python version compatibility...

✅ Python compatibility check complete: 11 package(s) incompatible with Python 3.8 (0 direct, 11 transitive)
```

### Step 5: Dependency diff against a git ref

```bash
# Compare the sample-project lockfile against the main branch
uv-sbom --diff main -p examples/sample-project -f markdown

# Compare against a file (e.g., a saved snapshot of uv.lock)
uv-sbom --diff /path/to/old/uv.lock -p examples/sample-project -f json
```

**What you will see:** A diff report listing Added, Removed, Updated, and
Unchanged packages between the base ref and the current lockfile.

### Step 6: All checks via config file

```bash
uv-sbom -p examples/sample-project -f markdown \
  -c examples/sample-project/config/uv-sbom.config.yml
```

This exercises CVE, license, and abandoned detection in a single run.

## Filtering by dependency groups

`--exclude-groups` removes packages that are reachable *only* through the specified
dependency groups (dev, test, lint, etc.). A package that is also a production dependency
is always retained.

```bash
# Exclude the test group via CLI flag
uv-sbom -p examples/sample-project --exclude-groups test -f markdown

# Exclude the dev and test groups at once
uv-sbom -p examples/sample-project --exclude-groups dev,test -f markdown

# Exclude all non-default groups at once (production-only SBOM)
uv-sbom -p examples/sample-project --production-only -f markdown

# Via config file (exclude_groups already set in config/uv-sbom.config.yml)
uv-sbom -p examples/sample-project -f markdown \
  -c examples/sample-project/config/uv-sbom.config.yml
```

**What you will see:** `pytest`, `pytest-cov`, and their exclusive transitive dependencies
(`colorama`, `coverage`, `iniconfig`, `packaging`, `pluggy`, `pygments`) are absent from
the filtered output. Running without any filter flag shows the full set including those
packages.

> **Known limitation**: Due to [#645](https://github.com/Taketo-Yoda/uv-sbom/issues/645),
> the `dev`-named group (`ruff`, `mypy`) is not correctly excluded by `--exclude-groups dev`
> or `--production-only`. This will be fixed in a follow-up issue.

## Contrast with other examples

| | `examples/sample-project` | `examples/abandoned-packages-project` | `examples/suggest-fix-project` | `examples/workspace` |
|---|---|---|---|---|
| Primary feature | CVE + license + abandoned | `--check-abandoned` (focused) | `--suggest-fix` Upgrade Advisor | `--workspace` mode |
| Vulnerable packages | Direct dependencies | None | Transitive dependencies | N/A |
| Abandoned demo | Partial (depends on PyPI state) | ✅ Yes (4 packages, always flagged) | ❌ Not focused | ❌ Not focused |
| Config file | ✅ Yes (`config/`) | ❌ No | ❌ No | ❌ No |

Use `abandoned-packages-project` to explore `--check-abandoned` in isolation with guaranteed output.
