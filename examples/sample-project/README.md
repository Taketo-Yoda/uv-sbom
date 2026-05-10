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
| Abandoned package detection | `--check-abandoned` | Several packages with no upstream release ≥ 730 days |

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

### Step 4: All checks via config file

```bash
uv-sbom -p examples/sample-project -f markdown \
  -c examples/sample-project/config/uv-sbom.config.yml
```

This exercises CVE, license, and abandoned detection in a single run
(once Issue #565 adds `check_abandoned: true` to the config file).

## Contrast with other examples

| | `examples/sample-project` | `examples/suggest-fix-project` | `examples/workspace` |
|---|---|---|---|
| Primary feature | CVE + license + abandoned | `--suggest-fix` Upgrade Advisor | `--workspace` mode |
| Vulnerable packages | Direct dependencies | Transitive dependencies | N/A |
| Abandoned demo | ✅ Yes | ❌ Not focused | ❌ Not focused |
| Config file | ✅ Yes (`config/`) | ❌ No | ❌ No |
