# non-pypi-sources-project

An example project demonstrating the `--check-non-pypi` feature of `uv-sbom` using a
`uv.lock` that contains real git, private-registry, and direct-URL sources alongside a
standard PyPI package.

## Purpose

`--check-non-pypi` classifies each package's source directly from `uv.lock`. No shipped
example project used to contain a non-PyPI source, so running the flag against
`sample-project` always produced an empty "Non-PyPI Package Sources" section.

This project's `uv.lock` was hand-crafted with a mix of source types so the flag always
produces real, non-empty output.

## Non-PyPI Sources in This Example

| Package | Version | Source Type | Direct/Transitive | In report? |
|---------|---------|--------------|--------------------|------------|
| acme-analytics-sdk | 1.4.0 | Private Registry | Direct | ✅ Yes |
| telemetry-agent | 0.9.2 | Git | Transitive | ✅ Yes |
| edge-config | 2.1.0 | Direct URL | Transitive | ✅ Yes |
| vendored-parser | 0.5.0 | Local Path | Direct | ❌ No (excluded by design) |
| requests | 2.32.3 | PyPI | Direct | ❌ No (canonical registry, for contrast) |

## Prerequisites

- `uv-sbom` built from source (`cargo build --release`) or installed
- No network access required for `--check-non-pypi` itself — it reads classification
  directly from `uv.lock`. (License lookups will show 404 warnings for the fictional
  packages in this example; this is expected and does not affect the non-PyPI report.)

## Usage

### Step 1: Non-PyPI source detection

```bash
# From the repository root
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --no-check-cve -f markdown
```

**Actual rendered output:**

```markdown
## ⚠️ Non-PyPI Package Sources

3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive).

| Package | Version | Source Type | Source |
|---------|---------|-------------|--------|
| acme-analytics-sdk | 1.4.0 | Private Registry | https://pypi.acme-corp.example/simple |
| edge-config | 2.1.0 | Direct URL | https://downloads.acme-corp.example/edge-config-2.1.0-py3-none-any.whl |
| telemetry-agent | 0.9.2 | Git | https://github.com/acme-corp/telemetry-agent?rev=9f2c1ab |

> Packages from non-PyPI sources may not be subject to PyPI's security policies. Review each package's origin before production deployment.
```

`vendored-parser` (Local Path) and `requests` (standard PyPI) are correctly **not** listed.

### Step 2: Combined with other checks

```bash
uv-sbom -p examples/non-pypi-sources-project --check-non-pypi --check-cve -f markdown
```

`requests==2.32.3` is a real, currently-installable PyPI release and may carry real,
currently-known vulnerabilities — that output will vary over time as new advisories are
published, which is why Step 1 uses `--no-check-cve` to keep this demo focused solely on
non-PyPI source detection.

## Why the Path Source and Standard PyPI Package Are Not Flagged

`--check-non-pypi` only flags **Private Registry**, **Git**, and **Direct URL** sources.
Local filesystem paths (`path = "..."`) and workspace members are intentionally excluded
— these are expected in normal uv workspace layouts, not external supply-chain risk. The
standard PyPI registry (`https://pypi.org/simple`) is, by definition, not "non-PyPI."

`vendored-parser`'s `path = "vendor/vendored-parser"` target does not need to exist on
disk — `--check-non-pypi` reads source classification as text from `uv.lock` and never
resolves the path.

## Why Not Just Use `sample-project`?

`examples/sample-project/uv.lock` contains only standard PyPI registry sources (and one
workspace-root entry). Running `--check-non-pypi` against it always produces zero
matches, so it cannot demonstrate the feature.

This project's `uv.lock` was built specifically to exercise every flagged source type
(`Private Registry`, `Git`, `Direct URL`) plus the two excluded types (`Local Path`,
standard `PyPI`) for contrast.

## Contrast with Other Examples

| | `examples/non-pypi-sources-project` | `examples/sample-project` | `examples/abandoned-packages-project` | `examples/suggest-fix-project` |
|---|---|---|---|---|
| Primary feature | `--check-non-pypi` (focused) | CVE + license + abandoned | `--check-abandoned` (focused) | `--suggest-fix` Upgrade Advisor |
| Non-PyPI demo | ✅ Yes (3 flagged, 2 excluded for contrast) | ❌ No (all packages are PyPI) | ❌ Not focused | ❌ Not focused |
| Vulnerable packages | `requests` (real, current CVEs) | Direct dependencies | None | Transitive dependencies |
| Config file | ❌ No | ✅ Yes (`config/`) | ❌ No | ❌ No |
