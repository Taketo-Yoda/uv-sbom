# Issue Label Conventions (canonical)

Single source of truth for which label an Issue gets when that is not obvious from the
label list. Established by Issue #923, after #917 and #918 were both filed as
`enhancement` and #918's branch had to be renamed from `feature/` to `docs/`.

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
