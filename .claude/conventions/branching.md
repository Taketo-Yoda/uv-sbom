# Branching Conventions (canonical)

Single source of truth for branch naming, branch base, PR base, and Stacked Mode.
Skills and docs under `.claude/` reference the sections below by heading instead of
restating them. If a restated copy anywhere disagrees with this file, this file wins
and the copy must be corrected (or, better, replaced with a pointer).

Established by Issue #849 after the same `origin/develop` fact had to be fixed in
three separate Issues (#838, #843, #846) and the label→prefix table had drifted
(`doc/` vs. `docs/`).

## Protected Branches

- `main` and `develop` never receive direct commits or pushes — changes land only
  via Pull Request.
- `develop` is the integration branch; `main` receives release and hotfix PRs only.

## Branch Naming (label → prefix)

Format: `<prefix>/<issue-number>-<short-description>`

| Priority | Issue Label | Branch Prefix | Example |
|----------|-------------|---------------|---------|
| 1 | `enhancement` | `feature/` | `feature/84-agent-skills` |
| 2 | `bug` | `bugfix/` | `bugfix/42-fix-parsing` |
| 3 | `refactor` | `refactor/` | `refactor/30-cleanup-code` |
| 4 | `documentation` | `docs/` | `docs/50-update-readme` |
| 5 | (no label) | `feature/` | `feature/99-misc-task` |

- **Multiple labels**: the highest-priority (lowest number) matching row wins — e.g.
  an Issue labeled `documentation` + `refactor` uses `refactor/`.
- **Additional prefixes** not derived from labels:
  - `hotfix/<issue>-<desc>` — critical production fixes (targets `main`)
  - `release/...` — used only by `/release`
  - `bugfix/<CVE-or-GHSA-ID>` — security fixes created by `/dependabot`

## Branch Base

**Normal Mode (default)**: always branch from `origin/develop`, never from `main`.

```bash
git fetch origin
git checkout -b <prefix>/<issue>-<desc> origin/develop
```

**Stacked Mode** (see below) chooses the base per this table:

| Mode | Base for `git checkout -b` |
|------|------------------------------|
| Normal (default) | `origin/develop` |
| Stacked, this is the first Issue in the stack | `origin/develop` (this Issue becomes the stack's bottom layer) |
| Stacked, a previous Issue's branch in this stack is still open (not yet merged) | that previous Issue's branch (fetch it first: `git fetch origin <previous-branch>`) |
| Stacked, but the previous Issue's PR has already merged (or was closed) | `origin/develop` (the stack has "landed" — start a fresh bottom layer) |

**Exceptions that are always `origin/develop`, even in Stacked Mode**:
- Security-fix branches created by `/dependabot` (never stacked — rationale in that
  skill's Step 3).
- `/commit`'s wrong-branch error-recovery path (rationale in that skill's
  "Step 0: Verify Branch (MANDATORY)" → "If on `develop` or `main`").

## PR Base

| Branch Type | Normal Mode | Stacked Mode |
|-------------|-------------|--------------|
| `feature/*`, `bugfix/*`, `docs/*`, `refactor/*` | `develop` | the still-open sibling PR's branch recorded by `/implement` Step 3 |
| `bugfix/<CVE-or-GHSA-ID>` (`/dependabot`) | `develop` | `develop` (never stacked) |
| `hotfix/*` | `main` | `main` |
| `release/*` | `main` (via `/release`'s flow) | n/a |

**`$BASE_BRANCH`**: skills that diff or target "the base" use the variable
`$BASE_BRANCH`, meaning the base resolved by the table above for the current branch
(`origin/develop`/`develop` in Normal Mode, the sibling stack branch in Stacked Mode).
Use it instead of a hardcoded `origin/develop` so a lower stack layer's changes are
not attributed to the current Issue. `/pr` Step 3 owns the resolution procedure.

## Stacked Mode (opt-in)

A PR whose base branch points at another still-open PR's branch is automatically
recognized by GitHub as part of a dependency chain ("stack") — public preview since
2026-07-30. Each PR in the stack shows only its own isolated diff for review, and
merging the bottom-most PR automatically rebases the rest of the stack.

**Entry rule (MANDATORY)**: Stacked Mode is entered **only** on an explicit user
request in the current session — e.g. "スタック型PRで進めて", "stack this on top of
#N", "implement these iteratively as a stack". **Never infer Stacked Mode** from
branch state, open-PR state, or the fact that several Issues are being implemented in
sequence. If in doubt, ask; the safe default is Normal Mode.

**Why it's opt-in**: it changes merge mechanics (asynchronous merge REST API instead
of `gh pr merge`, see `.claude/skills/pr/SKILL.md` → "Merging a Stacked PR (Stacked Mode only)") and CI
visibility per layer, so it must be a deliberate choice, not an inferred one.

**Scope**: once entered, Stacked Mode is **session-scoped and sticky** — it applies to
every Issue implemented for the rest of the current session unless the user says
otherwise. `/implement` Step 3 restates the resolved mode for each Issue via its
`Stack position:` line, so the current mode stays visible and can be corrected at
any time.

## Who Merges

Claude never merges PRs into `develop`/`main` on its own judgment. The full rule
lives in `.claude/skills/pr/SKILL.md` → "Who merges" (its only executing consumer).
