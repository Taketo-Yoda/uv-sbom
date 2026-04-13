# workspace

A minimal but realistic [uv workspace](https://docs.astral.sh/uv/concepts/projects/workspaces/)
with two member packages, designed to demonstrate `uv-sbom --workspace`.

## Structure

```
workspace/
├── pyproject.toml          # Workspace root — declares [tool.uv.workspace]
├── uv.lock                 # Committed lock file shared by all members
├── packages/
│   ├── api/
│   │   └── pyproject.toml  # Web-API service: requests, fastapi
│   └── worker/
│       └── pyproject.toml  # Background worker: celery, redis
```

## Prerequisites

- `uv-sbom` installed or built from source (`cargo build --release`)
- No `uv` required — the lock file is already committed

## Usage

### Generate one SBOM per member (CycloneDX JSON, default)

```bash
# From the repository root
uv-sbom --workspace --path examples/workspace
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
api                  examples/workspace/packages/api/sbom.json
worker               examples/workspace/packages/worker/sbom.json
────────────────────────────────────────────────────────────
```

Each member gets its own `sbom.json` containing only the packages reachable
from that member (transitive dependencies are included, but packages belonging
to other members are excluded).

### Markdown output

```bash
uv-sbom --workspace --path examples/workspace --format markdown
```

This writes `sbom.md` files instead of `sbom.json`.

### With CVE check

```bash
uv-sbom --workspace --path examples/workspace --check-cve
```

## Member Dependencies

| Member | Direct Dependencies |
|--------|-------------------|
| `api` | `requests`, `fastapi` |
| `worker` | `celery`, `redis` |

The two members share the same `uv.lock` at the workspace root.
`uv-sbom` uses the lock file to resolve the full transitive dependency
tree for each member independently.

## Contrast with single-project examples

| | `examples/sample-project` | `examples/workspace` |
|---|---|---|
| Mode | Default (single project) | `--workspace` |
| Lock file location | Project root | Workspace root (shared) |
| SBOM output | `sbom.json` / `sbom.md` | One file per member |
