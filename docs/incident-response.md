# Incident Response (`--incident`)

[Back to README](../README.md)

When a new advisory is announced, `--incident` answers three questions for your project in one command: **am I affected, is the patch out, and what do I run?** The suggested upgrade command is verified with a dry-run resolution against your `uv.lock` (your lock file is never modified), and when the upgrade can't resolve, you get guidance instead.

## Table of Contents

- [Quick Start](#quick-start)
- [Stop Watching Advisories by Hand](#stop-watching-advisories-by-hand)
- [Accepted IDs](#accepted-ids)
- [Output Structure](#output-structure)
- [Workspaces (`--workspace`)](#workspaces---workspace)
- [Manual Range (Advisory Not Yet in OSV)](#manual-range-advisory-not-yet-in-osv)
- [Exit Codes](#exit-codes)
- [Scope Options and Mutual Exclusions](#scope-options-and-mutual-exclusions)

---

## Quick Start

```bash
uv-sbom --incident GHSA-v845-jxx5-vc9f
```

Real output against [`examples/suggest-fix-project`](../examples/suggest-fix-project) (exit code `1`):

````markdown
## Incident Report: GHSA-v845-jxx5-vc9f

- **Aliases**: CVE-2023-43804, PYSEC-2023-192
- **Severity**: MEDIUM
- **Summary**: `Cookie` HTTP header isn't stripped on cross-origin redirects
- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

The exit code tells you, or your script, what to do next:

| Exit code | Verdict | What to do next |
|-----------|---------|-----------------|
| `0` | Not affected | Nothing. Move on |
| `1` | Affected, fix released | Run the command in **Next action** |
| `4` | Affected, no released fix yet | Wait for a fix, and check again later (automate it below) |

## Stop Watching Advisories by Hand

`--incident` exits with `4` when your project is affected but no version that fixes the vulnerability has been released yet, so let a script or scheduler do the waiting. For example, copy [`wait-for-patch.sh`](../examples/incident-response/wait-for-patch.sh) into your project root, make it executable, and have it check once an hour:

```bash
POLL_INTERVAL=3600 ./wait-for-patch.sh GHSA-v845-jxx5-vc9f
```

[`examples/incident-response/`](../examples/incident-response/) ships two ready-to-use options, this script included:

- [`wait-for-patch.sh`](../examples/incident-response/wait-for-patch.sh): re-runs the check until the fix is out, then prints the report and optionally runs your own `ON_FIX_COMMAND` (a notification, an upgrade PR, and so on).
- [`incident-watch.yml`](../examples/incident-response/incident-watch.yml): a scheduled GitHub Actions workflow. It succeeds with "still waiting" while you wait, and fails, with the report in the job summary, once the fix is released.

uv-sbom does not monitor anything. Your cron job or CI schedule re-runs it, and it answers each time. It never modifies your `uv.lock`. Note that OSV can take a while to index a newly announced advisory. Until then, pass the affected range yourself ([#963](https://github.com/Taketo-Yoda/uv-sbom/issues/963)).

## Accepted IDs

IDs starting with `GHSA-`, `PYSEC-`, `CVE-`, `OSV-`, or `MAL-`. The prefix is case-insensitive. Any other value is read as a manual range (see below), and a value that is neither is rejected with exit code `2`. When the record you ask for lists no PyPI package (typical for a `CVE-` ID), uv-sbom follows its `GHSA-` and then `PYSEC-` aliases and notes which ID the report was resolved from.

```bash
# Look up a GHSA, PYSEC, CVE, OSV, or MAL ID
uv-sbom --incident GHSA-v845-jxx5-vc9f

# A CVE ID is resolved to its GHSA/PYSEC record automatically
uv-sbom --incident CVE-2023-43804 -p path/to/project

# JSON for automation, or write the report to a file
uv-sbom --incident GHSA-v845-jxx5-vc9f --format json
uv-sbom --incident GHSA-v845-jxx5-vc9f --output incident.md
```

## Output Structure

The report is **Markdown by default** (unlike SBOM generation, which defaults to JSON). It has three sections:

1. **Impact** — each package the advisory names, its locked version, the verdict, and whether it is a direct or transitive dependency (with dependency paths).
2. **Patch status** — the fixed version and whether it is released on PyPI.
3. **Next action** — a copy-paste `uv lock --upgrade-package <name>==<fixed>` + `uv sync` command. It is verified with a dry-run resolution first, and your `uv.lock` is not modified. If the upgrade cannot be resolved, or no fix is released, you get guidance instead. When the blocked package is itself a direct dependency, the guidance tells you to relax its version requirement in `pyproject.toml` to allow the fixed version.

Example against `examples/suggest-fix-project` (exit code `1`):

````markdown
## Incident Report: GHSA-v845-jxx5-vc9f

- **Aliases**: CVE-2023-43804, PYSEC-2023-192
- **Severity**: MEDIUM
- **Summary**: `Cookie` HTTP header isn't stripped on cross-origin redirects
- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

## Workspaces (`--workspace`)

In a uv workspace root, `--incident <ID> --workspace` checks every member in one run and prints **one combined report**: the advisory heading, a `1. Impact` subsection per member with that member's verdict and dependency paths, shared `2. Patch status` and `3. Next action` sections (the upgrade command is the same for every member, because the workspace shares one `uv.lock`), and a final "N of M members affected" line. The advisory and its PyPI release status are fetched once per run, not once per member, and the dry-run resolution runs against the workspace root. The exit code is the most actionable member verdict (using the same table as below). No per-member `sbom.*` file is written, and the report always goes to stdout (`--workspace` cannot be combined with `--output`).

```bash
uv-sbom --incident GHSA-82w8-qh3p-5jfq --workspace -p examples/workspace
```

Output against `examples/workspace`, where only the `api` member reaches `starlette` (through `fastapi`) (exit code `1`):

````markdown
## Incident Report: GHSA-82w8-qh3p-5jfq

- **Aliases**: CVE-2026-54283, PYSEC-2026-249
- **Severity**: HIGH
- **Summary**: Starlette: request.form() limits silently ignored for application/x-www-form-urlencoded enable DoS
- **Overall verdict**: Affected — fix released

### 1. Impact

#### Member: api

- **Verdict**: Affected — fix released
- **starlette** 1.0.0 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `fastapi → starlette`

#### Member: worker

- **Verdict**: Not affected

None of the affected packages (starlette) are reachable from this member.

### 2. Patch status

- **starlette**: fixed in 1.3.1 — released

### 3. Next action

**starlette** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package starlette==1.3.1
uv sync
```

**1 of 2 members affected**: api
````

**Workspace root dependency groups in incident mode:** like `--workspace` (see [uv Workspace Support](workspace.md)), `--incident --workspace` prints a warning on stderr naming each virtual-root `[dependency-groups]` group that is not excluded, because no member scope follows those groups and packages reachable only through them are not checked against the advisory. The warning is printed after the progress lines and before the report, only when the run succeeds. The report on stdout (Markdown or JSON) and the exit code are unchanged, so `--format json | jq` keeps working. Add the root groups to `--exclude-groups` (or use `--production-only`) to silence it. The stderr of the command above ends with:

```
⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

## Manual Range (Advisory Not Yet in OSV)

In the first hours after a disclosure, the advisory may not be in OSV yet, so an ID has nothing to look up. Security announcements usually state the affected range in plain text ("versions before 2.0.6 are affected"), so you can pass that range instead of an ID: a package name immediately followed by one or more comma-separated specifiers.

```bash
uv-sbom --incident "foo<2.3.2"          # affected below 2.3.2; 2.3.2 is the fix
uv-sbom --incident "foo>=2.0,<2.3.2"    # affected from 2.0 up to (not including) 2.3.2
uv-sbom --incident "foo<=2.3.1"         # affected up to 2.3.1; no fix known yet
```

| Specifier | Meaning |
|-----------|---------|
| `>=X` | First affected version (optional; without it, every version below the upper bound is affected) |
| `<X` | Fixed version. Patch status and the verified upgrade command work exactly as with an advisory ID |
| `<=X` | Last affected version. No fix is known, so the verdict is "no fix available" (exit `4`) |

- **Quote the argument.** In the shell, `<` is an input redirection: `uv-sbom --incident foo<2.3.2` would try to read a file named `2.3.2`.
- Only `>=`, `<`, and `<=` are accepted, with at most one lower bound and one upper bound (not `<` and `<=` together). Other operators (`==`, `!=`, `~=`, `>`, `===`), a bare package name, and a range that contains no versions (e.g. `"foo>=2.3,<2.0"`) are rejected with exit code `2`, not guessed.
- With `>=` alone, the verdict is also "no fix available" (exit `4`).
- One range per run. For fixes on several release lines, run the command once per range.
- No OSV request is made. The report header shows the range and states that it was supplied by you and not verified against a vulnerability database. In JSON output, `source` is `"manual"` (it is `"osv"` for an advisory ID), and `advisory_id` holds the range.
- Works with `--workspace`, `--format json`, and `--lang ja`, the same as an advisory ID, with the same exit codes.

Example against `examples/suggest-fix-project` (exit code `1`):

````markdown
## Incident Report (manual range): `urllib3<2.0.6`

⚠️ This affected range was supplied by you. It is not taken from a vulnerability database and has not been verified.

- **Overall verdict**: Affected — fix released

### 1. Impact

- **urllib3** 2.0.4 — Affected — fix released (transitive dependency)
  - Dependency path(s):
    - `requests → urllib3`

### 2. Patch status

- **urllib3**: fixed in 2.0.6 — released

### 3. Next action

**urllib3** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package urllib3==2.0.6
uv sync
```
````

## Exit Codes

| Verdict | Exit Code |
|---------|-----------|
| Not affected (including an advisory that names no PyPI package) | 0 |
| Affected, fix released | 1 |
| Affected, fix not yet released, or no fix available | 4 |
| Unknown advisory ID, network error, or other application error | 3 |
| Malformed advisory ID or range, or conflicting flags | 2 |

## Scope Options and Mutual Exclusions

**Scope options honored:** `--path`, `--exclude`, `--exclude-groups`, `--production-only`, `--output` (not with `--workspace`), `--format`, `--lang`, and `--config`. The config file's `exclude_packages` and `exclude_groups` also apply.

**Ignored config keys:** the config file's `format` is never used in incident mode; only `--format` changes the output. However, an invalid `format` value in the config file is still rejected (exit code `3`), because config validation runs before mode dispatch. The vulnerability, license, maintenance, and compatibility check keys (`check_cve`, `severity_threshold`, `cvss_threshold`, `ignore_cves`, `check_license`, `license_policy`, `check_abandoned`, `check_non_pypi`, `check_exploitability`, `target_python`, `suggest_fix`, `baseline_file`) are ignored too.

**Mutual exclusion:** `--incident` cannot be combined with `--diff`, `--init`, `--dry-run`, `--explain`, `--show-dependency-tree`, `--no-check-cve`, `--baseline`, `--update-baseline`, `--suggest-fix`, `--check-license`, `--check-abandoned`, `--check-non-pypi`, `--check-exploitability`, `--target-python`, `--severity-threshold`, `--cvss-threshold`, `--ignore-cve`, or `--verify-links`. It can be combined with `--workspace` (see above).

**Config file key:** None. `--incident` is intentionally CLI-only: it is a one-off query about a single advisory (or range), not a persistent policy setting.
