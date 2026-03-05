# suggest-fix-project

An example project designed to demonstrate the `--suggest-fix` flag of `uv-sbom`.

## Purpose

This project contains **intentionally outdated direct dependencies** whose locked versions
introduce **vulnerable transitive packages**. It is designed so that:

- Upgrading one direct dependency (`httpx`) **can** resolve the transitive vulnerability
  → the `--suggest-fix` output shows an **Upgradable** recommendation.
- Upgrading another direct dependency (`requests`) **cannot** fully resolve the transitive
  vulnerability in a single upgrade step → the output shows an **Unresolvable** warning.

Both outcomes are real results produced by running `uv lock --upgrade-package` under the hood.

> ⚠️ **Do not use these package versions in production.** They are intentionally vulnerable
> for demonstration purposes only.

## Dependency Setup

| Direct Dependency | Locked Version | Transitive Dep | Transitive Version | CVE |
|-------------------|---------------|----------------|--------------------|-----|
| `httpx` | 0.24.1 | `h11` (via `httpcore`) | 0.14.0 | [GHSA-vqfr-h8mv-ghfj](https://github.com/advisories/GHSA-vqfr-h8mv-ghfj) CRITICAL |
| `requests` | 2.31.0 | `urllib3` | 2.0.4 | Multiple HIGH/MEDIUM CVEs |

### Why upgrading `httpx` fixes `h11` (Upgradable)

```
httpx 0.24.1  →  httpcore <0.18.0  →  h11 0.14.x   (CRITICAL CVE)
httpx 0.28.1  →  httpcore ==1.*    →  h11 >=0.16.0  (FIXED)
```

When `uv lock --upgrade-package httpx` is run, httpx jumps to 0.28.1, which requires
`httpcore==1.*`. `httpcore 1.0.9+` in turn requires `h11>=0.16`, so uv resolves h11
to 0.16.0 — the fixed version.

### Why upgrading `requests` does NOT fix `urllib3` (Unresolvable)

```
requests 2.31.0  →  urllib3 >=1.21.1,<1.27  (locked: 2.0.4*)
requests 2.32.5  →  urllib3 >=1.21.1,<3     (still allows 2.0.4)
```

When `uv lock --upgrade-package requests` is run, requests upgrades to 2.32.5, but its
constraint on urllib3 is looser (`<3`), so uv keeps urllib3 at 2.0.4. The urllib3 2.x
CVEs require upgrading urllib3 directly — something outside the scope of what upgrading
`requests` alone can achieve.

> *Note: The lock resolved to urllib3 2.0.4 because it was the latest version available
> at the time the lock was created (2023-09-01 cut-off).

## Prerequisites

- `uv-sbom` built from source (`cargo build --release`) or installed
- `uv` CLI available in PATH (required for `--suggest-fix`)

## Usage

### Step 1: Basic CVE check (no upgrade suggestions)

```bash
# From the repository root
uv-sbom -p examples/suggest-fix-project --check-cve -f markdown
```

**What you will see:**
- Vulnerability Report table listing CVEs for `h11`, `urllib3`, and `requests`
- Vulnerability Resolution Guide showing which direct dep introduces each transitive CVE
- **No "Recommended Action" column** (--suggest-fix not used)

### Step 2: With Upgrade Advisor (`--suggest-fix`)

```bash
uv-sbom -p examples/suggest-fix-project --check-cve --suggest-fix -f markdown
```

**What you will see in the Resolution Guide:**

| Vulnerable Package | Introduced By | Recommended Action |
|--------------------|--------------|-------------------|
| `h11` 0.14.0 | `httpx` (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) |
| `urllib3` 2.0.4 | `requests` (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 |

### Step 3: CycloneDX output with upgrade properties

```bash
uv-sbom -p examples/suggest-fix-project --check-cve --suggest-fix -f cyclonedx
```

**What you will see:**
- Vulnerability entries with additional `properties`:
  - `uv-sbom:recommended-action`: human-readable recommendation
  - `uv-sbom:resolved-version`: the transitive dep version after simulated upgrade

### Step 4: Filter by severity

```bash
# Only show HIGH and CRITICAL vulnerabilities
uv-sbom -p examples/suggest-fix-project --check-cve --suggest-fix \
  --severity-threshold high -f markdown
```

## Expected Output Excerpt

```markdown
## Vulnerability Resolution Guide

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action | Vulnerability ID |
|--------------------|---------|--------------|---------|----------------------------|-------------------|-----------------|
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) | GHSA-vqfr-h8mv-ghfj |
| urllib3 | 2.0.4 | 2.6.0 | 🟠 HIGH | requests (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 which does not satisfy >= 2.6.0 | GHSA-2xpw-w6gg-jr37 |
```

## Contrast with `sample-project`

| | `examples/sample-project` | `examples/suggest-fix-project` |
|---|---|---|
| Vulnerable packages | All **direct** dependencies | All **transitive** dependencies |
| Resolution Guide | Not shown (no transitive CVEs) | Shown with Recommended Action |
| `--suggest-fix` output | No upgrade advice | Upgradable + Unresolvable cases |

Use `sample-project` to explore the basic CVE check and `--check-license` features.
Use this project to explore the `--suggest-fix` Upgrade Advisor feature.
