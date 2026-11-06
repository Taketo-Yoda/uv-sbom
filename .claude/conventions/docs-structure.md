# Documentation Structure Convention (canonical)

Single source of truth for the docs/ directory layout and the update obligation
when documentation changes. Established by Issue #1096, after the docs/ja/
directory was introduced in #1088.

## Directory Layout

```
docs/
├── security-checks.md
├── incident-response.md
├── dependency-insight.md
├── configuration.md
├── ci-integration.md
├── workspace.md
├── network.md
├── cli-reference.md
└── ja/
    ├── security-checks.md
    ├── incident-response.md
    ├── dependency-insight.md
    ├── configuration.md
    ├── ci-integration.md
    ├── workspace.md
    ├── network.md
    └── cli-reference.md
```

## Routing Table

Each English documentation file has a corresponding Japanese translation:

| English source | Japanese translation |
|----------------|---------------------|
| `docs/security-checks.md` | `docs/ja/security-checks.md` |
| `docs/incident-response.md` | `docs/ja/incident-response.md` |
| `docs/dependency-insight.md` | `docs/ja/dependency-insight.md` |
| `docs/configuration.md` | `docs/ja/configuration.md` |
| `docs/ci-integration.md` | `docs/ja/ci-integration.md` |
| `docs/workspace.md` | `docs/ja/workspace.md` |
| `docs/network.md` | `docs/ja/network.md` |
| `docs/cli-reference.md` | `docs/ja/cli-reference.md` |

## Update Checklist

When any `docs/<file>.md` is added or modified:

- [ ] The corresponding `docs/ja/<file>.md` is updated with the Japanese translation
- [ ] `README.md` links to `docs/<file>.md` (English landing page)
- [ ] `README-JP.md` links to `docs/ja/<file>.md` (Japanese landing page)

When a new `docs/<file>.md` is created:

- [ ] A corresponding `docs/ja/<file>.md` is created
- [ ] A row is added to the Routing Table above
- [ ] Both README.md and README-JP.md documentation tables are updated

## README Landing Page Rules

- **README.md**: links point to `docs/<file>.md` (English)
- **README-JP.md**: links point to `docs/ja/<file>.md` (Japanese); anchor
  fragments use Japanese heading text; no `（英語）` labels

## Consumers

- `.claude/skills/implement/SKILL.md` Step 4.3.B: includes `docs/ja/` update
  checkbox.
- `.claude/skills/pr/SKILL.md` Step 4.6.B: mirrors the same checkbox.
- `.claude/CLAUDE.md` → "README Update Checklist": links here for the full
  routing table.
