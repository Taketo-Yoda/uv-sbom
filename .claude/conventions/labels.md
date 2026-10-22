# Issue Label Conventions (canonical)

Single source of truth for which labels exist and which label an Issue gets when that
is not obvious from the list. Established by Issue #923, after #917 and #918 were both
filed as `enhancement` and #918's branch had to be renamed from `feature/` to `docs/`.

## Labels Reference

| Label | Purpose |
|-------|---------|
| `bug` | Bug fixes |
| `enhancement` | New features or improvements |
| `documentation` | Documentation updates |
| `refactor` | Code refactoring |
| `security` | Vulnerabilities or security-related issues |
| `ci` | CI/CD pipeline changes |
| `maintenance` | Maintenance tasks, dependency updates, CI/CD |
| `rust` | PRs that update Rust code |
| `dependencies` | PRs that update a dependency file |
| `good first issue` | Good for newcomers |
| `github_actions` | PRs that update GitHub Actions code |
| `priority: low` | Low priority, address when time permits |
| `priority: medium` | Normal priority |
| `priority: high` | High priority, address soon |

## Label for `.claude/`-only Issues

An Issue whose changes are confined to `.claude/` (skills, agents, conventions,
instructions) gets the `documentation` label. If the change is a structural
reorganization (moving, splitting, or merging those files without changing what they
instruct), it gets `refactor`. It never gets `enhancement`.

- **Why**: these changes give end users nothing they can observe. The tool behaves
  the same afterwards, so they are process work, not enhancements.
- **Why it matters**: the branch prefix is derived from the label
  (`branching.md` → "Branch Naming (label → prefix)"), so a wrong label gives a
  wrong branch name.
- **Mixed Issues**: if the Issue also changes `src/`, user-facing docs, or other
  shipped files, label it by that change instead.
- The CHANGELOG consequence (no entry) is owned by `changelog.md` → "What Needs an
  Entry".
