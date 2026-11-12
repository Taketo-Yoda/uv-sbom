# Dependency Insight

[Back to README](../README.md)

uv-sbom provides several features for understanding your dependency graph: tracing why a package is included, visualizing the tree structure, comparing changes between lock file versions, identifying which direct dependency introduces a vulnerable transitive package, and suggesting upgrades to resolve vulnerabilities.

## Table of Contents

- [Dependency Explanation (`--explain`)](#dependency-explanation---explain)
- [Dependency Tree Visualization (`--show-dependency-tree`)](#dependency-tree-visualization---show-dependency-tree)
- [Dependency Diff (`--diff`)](#dependency-diff---diff)
- [Vulnerability Resolution Guide](#vulnerability-resolution-guide)
- [Upgrade Advisor (`--suggest-fix`)](#upgrade-advisor---suggest-fix)
  - [Constraint-Dependencies Workaround](#constraint-dependencies-workaround)

---

## Dependency Explanation (`--explain`)

Use the `--explain <PACKAGE_NAME>` option to trace how a package ended up in your dependency tree. It answers "why is this package here?" by printing every path from a direct dependency down to the target package.

```bash
# Trace why idna is included
uv-sbom --explain idna --format markdown

# Combine with other options
uv-sbom --explain idna --no-check-cve --format markdown
```

**How it works:**
- Reuses the dependency graph already built for the Markdown report — no network access and no additional traversal
- Reports the package as a **direct dependency** when it appears in `[project.dependencies]`, and lists every transitive path otherwise (a package can be both)
- Paths read left to right, from the direct dependency to the target, using the same backtick-and-arrow notation as the Dependency Chains subsection
- An unknown or invalid package name is reported as "not found"; it never aborts SBOM generation
- The graph is built only from `[project.dependencies]`. Packages reachable only through `[dependency-groups]` (dev, test, lint, …) are reported as not found, even though they still appear in the component inventory and license tables

**Output:**
- **Dependency Explanation section**: a single `## Dependency Explanation` section in the Markdown output, rendered in one of three states — transitive paths, direct dependency, or not found
- When `--explain` is not passed, the section is omitted entirely

**Example output (transitive package reached by several paths):**
```markdown
## Dependency Explanation

**idna** is included via 3 path(s):

- `httpx` → `idna`
- `requests` → `idna`
- `httpx` → `httpcore` → `anyio` → `idna`
```

Produced by running against [`examples/suggest-fix-project`](../examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --explain idna --no-check-cve -f markdown
```

**Example output (direct dependency):**
```markdown
## Dependency Explanation

**requests** is a direct dependency of this project.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain requests --no-check-cve -f markdown
```

**Example output (package not found):**
```markdown
## Dependency Explanation

Package **definitely-not-a-real-package** was not found in this project's dependencies.
```

```bash
uv-sbom -p examples/suggest-fix-project --explain definitely-not-a-real-package --no-check-cve -f markdown
```

> **Note:** These examples use `examples/suggest-fix-project` rather than `examples/sample-project` (used elsewhere in this README) because it is the shipped example that actually contains a diamond dependency — `idna` is required by both `httpx` and `requests`.

**Config file equivalent:**

None. `--explain` is intentionally CLI-only: it is a one-off diagnostic query about a single package, not a persistent policy setting like `check_non_pypi` or `target_python`. It has no `uv-sbom.config.yml` key and does not appear in the Config File Schema Reference table.

**Flag interactions:**
- **`--workspace` is rejected.** The combination is a hard error at argument-parsing time:
  ```
  error: the argument '--explain <PACKAGE_NAME>' cannot be used with '--workspace'
  ```
- **`--format json` silently produces nothing.** CycloneDX JSON output never includes explain data, and unlike `--check-license` and `--verify-links`, no "no effect" warning is printed for this combination. Since `json` is the default format, always pass `--format markdown` (or `-f markdown`) with `--explain`.

## Dependency Tree Visualization (`--show-dependency-tree`)

Use `--show-dependency-tree` to render your project's dependency graph as an ASCII tree in the Markdown output. Use `--dependency-tree-depth <DEPTH>` (default: 3) to control how many levels below each direct dependency are expanded.

```bash
# Show the full dependency tree
uv-sbom --show-dependency-tree --format markdown

# Limit the tree to 2 levels below each root
uv-sbom --show-dependency-tree --dependency-tree-depth 2 --format markdown
```

**How it works:**
- Reuses the dependency graph already built for the Markdown report — no network access and no additional traversal
- One root per direct dependency, in the same order as the Direct Dependencies list; children follow the lock file's own dependency order
- Diamond dependencies (a package reachable through more than one path) are shown once under each parent, not deduplicated — the tree mirrors graph shape, not a flattened package list
- `--dependency-tree-depth` counts levels *below* each root: `0` shows roots only, `1` shows roots plus their immediate children, and so on
- When a branch has children that were not expanded because the depth limit was reached, a `... (truncated)` marker is shown in their place, followed by a note naming the depth that was applied

**Output:**
- **Dependency Tree section**: a single `## Dependency Tree` section in the Markdown output, containing only package name and version — license, description, and hash data are not repeated here since they already appear in the Component Inventory
- When `--show-dependency-tree` is not passed, the section is omitted entirely

**Example output (full tree, no truncation):**

Produced by running against [`examples/suggest-fix-project`](../examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   ├── idna (3.4)
│   │   │   └── sniffio (1.3.0)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```
````

**Example output (truncated at depth 2):**

```bash
uv-sbom -p examples/suggest-fix-project --show-dependency-tree --dependency-tree-depth 2 --no-check-cve -f markdown
```

````markdown
## Dependency Tree

```text
├── httpx (0.24.1)
│   ├── certifi (2023.7.22)
│   ├── httpcore (0.17.3)
│   │   ├── anyio (4.0.0)
│   │   │   └── ... (truncated)
│   │   ├── certifi (2023.7.22)
│   │   ├── h11 (0.14.0)
│   │   └── sniffio (1.3.0)
│   ├── idna (3.4)
│   └── sniffio (1.3.0)
└── requests (2.31.0)
    ├── certifi (2023.7.22)
    ├── charset-normalizer (3.2.0)
    ├── idna (3.4)
    └── urllib3 (2.0.4)
```

_Tree truncated at depth 2. Use `--dependency-tree-depth <DEPTH>` to show more levels._
````

> **Note:** These examples use `examples/suggest-fix-project` rather than `examples/sample-project` (used elsewhere in this README) because it is the shipped example with a chain deep enough (`httpx` → `httpcore` → `anyio` → `idna`/`sniffio`) to actually demonstrate truncation at a reduced depth.

**Config file equivalent:**

None. `--show-dependency-tree` is intentionally CLI-only: it is a one-off visualization request, not a persistent policy setting like `check_non_pypi` or `target_python`. It has no `uv-sbom.config.yml` key and does not appear in the Config File Schema Reference table.

**Flag interactions:**
- **`--format json` silently produces nothing.** CycloneDX JSON output never includes the dependency tree, and no "no effect" warning is printed for this combination. Since `json` is the default format, always pass `--format markdown` (or `-f markdown`) with `--show-dependency-tree`.

## Dependency Diff (`--diff`)

Use the `--diff` option to compare the current `uv.lock` against a previous version. This is useful for reviewing what changed between branches, tags, or arbitrary lockfile snapshots before merging.

```bash
# Compare against a git branch or tag
uv-sbom --diff main
uv-sbom --diff v1.2.0
uv-sbom --diff abc1234    # abbreviated commit SHA

# Compare against a file path (absolute or relative to CWD)
uv-sbom --diff /path/to/old/uv.lock

# Output as Markdown report
uv-sbom --diff main --format markdown --output diff.md

# Output as JSON
uv-sbom --diff main --format json
```

**Auto-detection:** If the argument resolves to an existing file on disk it is treated as a file path; otherwise it is treated as a git ref. Relative paths are resolved against the process working directory (not `--path`).

**Git ref validation:** Only `[a-zA-Z0-9._/-]` characters are allowed in git refs. Refs starting with `-` are also rejected. This prevents command injection.

**Mutual exclusion:** `--diff` cannot be combined with `--workspace` or `--init`.

### CVE Delta

By default, `--diff` also runs vulnerability checks on both the base and current lock files and appends a **CVE Delta** section to the report showing which vulnerabilities were introduced or resolved:

- **New vulnerabilities** — CVEs that affect packages in the current lock but were not present in the base.
- **Resolved vulnerabilities** — CVEs that affected packages in the base lock but no longer apply.

```bash
# Diff with CVE delta (default — CVE checking is on)
uv-sbom --diff main

# Disable CVE checking in diff mode
uv-sbom --diff main --no-check-cve
```

JSON output includes a top-level `cve_delta` key with `new` and `resolved` arrays. The key is omitted entirely when `--no-check-cve` is passed.

**Severity and CVSS filtering:** `--severity-threshold` and `--cvss-threshold` apply to the CVE delta. Only entries at or above the threshold appear in the tables. The process exits with code `1` when new CVEs above the configured threshold are introduced.

```bash
# Show only HIGH and above CVE delta entries
uv-sbom --diff main --severity-threshold high

# Show only CVE delta entries with CVSS ≥ 7.0
uv-sbom --diff main --cvss-threshold 7.0
```

**CI example:**
```bash
# Fail the build if new dependencies introduced by this PR have known HIGH+ CVEs
uv-sbom --diff origin/main --format markdown --output diff.md --severity-threshold high
```

## Vulnerability Resolution Guide

When vulnerabilities are detected in transitive dependencies, uv-sbom automatically generates a **Vulnerability Resolution Guide**. This section shows which direct dependency introduces each vulnerable transitive package, so you know exactly what to upgrade.

### Markdown output example

```markdown
## Vulnerability Resolution Guide

The following transitive dependencies have known vulnerabilities. The table shows which direct dependency introduces each vulnerable package.

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Vulnerability ID |
|--------------------|---------|---------------|----------|---------------------------|-----------------|
| urllib3 | 1.26.15 | >= 2.0.7 | 🟠 HIGH | requests (2.31.0) | [CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX) |
| h11 | 0.14.0 | >= 0.14.4 | 🟠 HIGH | httpx (0.24.0) | [CVE-2024-ZZZZZ](https://nvd.nist.gov/vuln/detail/CVE-2024-ZZZZZ) |

### Dependency Chains

**`h11 0.14.0`** — CVE-2024-ZZZZZ (HIGH)
- `httpcore` → `httpx` → **`h11 0.14.0`** ⚠️
```

> **Note:** The `### Dependency Chains` subsection is only rendered when at least one vulnerable package is reachable via a multi-hop chain (chain length > 2). It is omitted entirely when all vulnerable packages are introduced directly by a first-level dependency.

### CycloneDX JSON output

In CycloneDX format, the introducing dependency is included as a `properties` entry:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-XXXXX",
      "properties": [
        {
          "name": "uv-sbom:introduced-by",
          "value": "requests@2.31.0"
        }
      ]
    }
  ]
}
```

> **Note:** The resolution guide only appears for **transitive** dependency vulnerabilities. Direct dependency vulnerabilities are shown in the standard vulnerability table, as users can upgrade them directly.

## Upgrade Advisor (`--suggest-fix`)

Use `--suggest-fix` to automatically suggest which direct dependency version to upgrade to resolve each transitive vulnerability.

**Requires**:
- `uv` CLI installed
- `pyproject.toml` in the project directory

**Example**:
```bash
uv-sbom generate --suggest-fix
```

**Output**: Adds a "Recommended Action" column to the Vulnerability Resolution Guide showing:
- `⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)` — when an upgrade fixes the vulnerability
- `⚠️ Cannot resolve: latest httpx still pins idna < 3.7` — when no upgrade helps (see [Constraint-Dependencies Workaround](#constraint-dependencies-workaround) below for what happens next)
- `❓ Could not analyze: <error>` — when simulation failed

**Try it with the included example**:

```bash
# This example has transitive CVEs designed to show both Upgradable and Unresolvable outcomes
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

See [`examples/suggest-fix-project/README.md`](../examples/suggest-fix-project/README.md) for a full walkthrough.

### Constraint-Dependencies Workaround

When upgrading the direct dependency alone cannot resolve a transitive vulnerability, `--suggest-fix` goes one step further: it suggests adding a [`[tool.uv].constraint-dependencies`](https://docs.astral.sh/uv/concepts/dependencies/#constraint-dependencies) entry to force the transitive package to a safe version.

**How it works:**

1. For each "Unresolvable" result, uv-sbom constructs a constraint `"<package>>=<fixed_version>"`.
2. It simulates `uv lock` with that constraint applied via `--override` to check whether the resolution succeeds.
3. The result is appended to the "Recommended Action" column in the Vulnerability Resolution Guide.

**Three possible outcomes:**

| Outcome | Indicator | Meaning |
|---------|-----------|---------|
| Verified | `💡 Workaround: add "pkg>=X.Y" to [tool.uv].constraint-dependencies (✅ verified: resolves to Z.W)` | The constraint works — adding it to `pyproject.toml` will force the safe version |
| Does not resolve | `💡 Tried constraint "pkg>=X.Y" — does not resolve: <reason>` | The constraint was tried but does not fix the vulnerability (e.g., other constraints prevent the version from being selected) |
| Simulation failed | `⚠️ Could not verify constraint "pkg>=X.Y": <error>` | The simulation could not run (e.g., the fixed version string is not a valid PEP 440 version) |

**Example output:**

Produced by running against [`examples/suggest-fix-project`](../examples/suggest-fix-project):

```bash
uv-sbom -p examples/suggest-fix-project --suggest-fix -f markdown
```

```markdown
## Vulnerability Resolution Guide

| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action | Vulnerability ID |
|--------------------|---------|---------------|----------|----------------------------|--------------------|------------------|
| h11 | 0.14.0 | 0.16.0 | 🔴 CRITICAL | httpx (0.24.1) | ⬆️ Upgrade httpx → 0.28.1 (resolves h11 to 0.16.0) | GHSA-vqfr-h8mv-ghfj |
| urllib3 | 2.0.4 | 2.6.0 | 🟠 HIGH | requests (2.31.0) | ⚠️ Cannot resolve: upgrading requests still resolves urllib3 to 2.0.4 which does not satisfy >= 2.6.0 💡 Workaround: add `"urllib3>=2.6.0"` to `[tool.uv].constraint-dependencies` (✅ verified: resolves to 2.8.0) | GHSA-2xpw-w6gg-jr37 |
| idna | 3.4 | 3.7 | 🟡 MEDIUM | httpx (0.24.1), requests (2.31.0) | ⚠️ Cannot resolve: upgrading httpx still resolves idna to 3.4 which does not satisfy >= 3.7 💡 Workaround: add `"idna>=3.7"` to `[tool.uv].constraint-dependencies` (✅ verified: resolves to 3.20) | GHSA-jjg7-2v4v-x38h |
```

_(Excerpt — vulnerability counts and resolved versions may change as new CVEs are published.)_

**Applying the workaround:**

When you see a verified constraint suggestion, add it to your `pyproject.toml`:

```toml
[tool.uv]
constraint-dependencies = [
    "urllib3>=2.6.0",
    "idna>=3.7",
]
```

Then re-lock and sync:

```bash
uv lock
uv sync
```

> **Note:** `constraint-dependencies` applies a lower bound without changing which packages are selected — it only constrains the version resolver. This is different from adding the package as a direct dependency. See the [uv documentation](https://docs.astral.sh/uv/concepts/dependencies/#constraint-dependencies) for details.

> **Workspace limitation:** The constraint simulation copies only the root `pyproject.toml` into its temporary environment. In a workspace with member-level `pyproject.toml` files, the simulation may not reflect member-specific constraints.
