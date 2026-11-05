# uv Workspace Support

[Back to README](../README.md)

[uv workspaces](https://docs.astral.sh/uv/concepts/projects/workspaces/) let you manage multiple Python packages in a single repository with a shared `uv.lock` file. `uv-sbom --workspace` generates a separate SBOM for each member package, reflecting only the dependencies reachable from that member.

## Table of Contents

- [When to Use](#when-to-use)
- [Usage](#usage)
- [Aggregate Summary](#aggregate-summary)
- [Workspace Root Dependency Groups](#workspace-root-dependency-groups)
- [With Other Options](#with-other-options)

---

## When to Use

- Your repository contains multiple Python packages (e.g., `api/`, `worker/`)
- You need per-member SBOMs for independent security scanning or compliance reporting

## Usage

```bash
# Generate one SBOM per workspace member (CycloneDX JSON, default)
uv-sbom --workspace --path /path/to/workspace
```

**Expected output:**

```
Workspace mode: 2 members found

  Processing: api
  ...
  Processing: worker
  ...

📦 Workspace SBOM Summary
────────────────────────────────────────────────────────────
Member               Output File
────────────────────────────────────────────────────────────
api                  /path/to/workspace/packages/api/sbom.json
worker               /path/to/workspace/packages/worker/sbom.json
────────────────────────────────────────────────────────────

📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

Each member gets its own `sbom.json` containing only the packages reachable from that member. Transitive dependencies are included, but packages belonging to other members are excluded.

## Aggregate Summary

After the per-member table, `--workspace` also prints an aggregate summary showing monorepo-wide health without opening every member's SBOM file — total CVE count, which members have license policy violations, and which members have abandoned / non-PyPI / Python-incompatible packages flagged. A line only appears for a check that was actually enabled for the run (e.g. `--check-license`); a check that wasn't run never prints a line, even an empty one.

## Workspace Root Dependency Groups

A virtual workspace root (a root `pyproject.toml` with no `[project]`) can declare its own `[dependency-groups]`, for example a `lint` group for repository-wide tooling. No member SBOM follows those groups, so `--workspace` prints a warning on stderr naming each root group that is not excluded, as in the last lines of the output above (`examples/workspace` declares `lint = ["ruff"]` at its root). Packages a member reaches through its own dependencies still appear in that member's SBOM. To silence the warning, add the root groups to `--exclude-groups` (or use `--production-only`). stdout and the member SBOM files are unchanged. A root with a `[project]` is a member itself, and its groups are covered by its own SBOM.

## With Other Options

```bash
# Markdown output for all members
uv-sbom --workspace --path examples/workspace --format markdown

# With license compliance check
uv-sbom --workspace --path examples/workspace --check-license
```

```
📊 Workspace Aggregate Summary
────────────────────────────────────────────────────────────
Total actionable CVEs: 28
Members with license policy violations: none
────────────────────────────────────────────────────────────

⚠️  Warning: Workspace root dependency group(s) not covered by any member SBOM: lint
   Packages reachable only through these groups are not in any SBOM. Add them to --exclude-groups to silence this warning.
```

> **Note:** `--workspace` and `--output` are mutually exclusive. In workspace mode, each member's SBOM is automatically written to `sbom.json` (or `sbom.md` for Markdown) inside the member's own directory.

See [`examples/workspace/`](../examples/workspace/) for a runnable demo with two member packages (`api` and `worker`).
