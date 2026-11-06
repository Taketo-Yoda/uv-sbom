# Documentation Structure (canonical)

Single source of truth for where user-facing documentation lives and how new
content is routed after the README restructuring in #1064.

## Structure

README.md and README-JP.md are **landing pages** (~250 lines). They contain
badges, a hero section, a quick-start block, and 2–3 line feature summaries
with links to the appropriate `docs/` file. Detailed documentation — examples,
tables, option lists, configuration schemas — lives exclusively in `docs/`.

## Routing Table

When adding or updating user-facing documentation for a CLI flag, config key,
or feature, route the **detailed content** to the correct `docs/` file:

| Content type | Target file |
|---|---|
| Security features (CVE, license, abandoned, non-PyPI, Python compat, exploitability, link verification, input validation) | `docs/security-checks.md` |
| Incident response (`--incident`) | `docs/incident-response.md` |
| Dependency insight (`--explain`, `--show-dependency-tree`, `--diff`, resolution guide, upgrade advisor) | `docs/dependency-insight.md` |
| Configuration file keys, schema reference, merge/priority rules, exclude patterns, dependency groups | `docs/configuration.md` |
| CI integration, exit codes, GitHub Actions / GitLab CI examples, scripting | `docs/ci-integration.md` |
| Workspace mode (`--workspace`) | `docs/workspace.md` |
| Network requirements, firewall, proxy, offline mode | `docs/network.md` |
| CLI options listing, output format examples | `docs/cli-reference.md` |

## README Landing Page Rules

- **README.md**: Add at most a 1-line summary + `docs/` link in the Feature
  Highlights section, only if the feature is significant enough. Never add a
  full subsection, config table, or multi-line example.
- **README-JP.md**: Mirror only the landing-page summary line (translated to
  Japanese). Link to the English `docs/` file with a `（英語）` notation.
- **python-wrapper/README.md**: Update only when changes affect installation,
  basic usage examples, or version/badge updates.

## Update Checklist

Trigger this checklist when **any** of the following is true:
- A `docs/*.md` file is being changed
- README.md or README-JP.md content is being changed
- A new CLI flag or config key was added
- A new user-facing feature was implemented

When triggered, check:

| File | Action Required | Notes |
|---|---|---|
| `docs/<target>.md` | Add detailed content per routing table | Primary documentation home |
| `docs/cli-reference.md` | Update CLI options listing if a flag was added/changed | Always |
| README.md | Add/update 1-line summary + link (if significant) | Landing page only |
| README-JP.md | Translate the README.md summary line | Landing page only |
| python-wrapper/README.md | Reflect if applicable | PyPI-focused, keep concise |

## Consumers

- `/implement` Step 4.3 — CLI Flag Documentation Gate (sub-checks A and B)
- `/pr` Step 4.6 — CLI Flag Documentation Backstop (sub-checks A and B)
- `CLAUDE.md` → "README Update Checklist" (links here)
