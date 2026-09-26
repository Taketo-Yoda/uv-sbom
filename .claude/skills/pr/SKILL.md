---
name: pr
description: Create Pull Requests with pre-flight checks and proper formatting
---

# /pr - Pull Request Creation Skill

Create Pull Requests that pass CI before creation and target the correct branch.

## Language Requirement

**IMPORTANT**: All Pull Requests MUST be written in **English**.

- PR title: English
- PR body: English
- Commit messages: English

## Stacked Mode (opt-in)

Entered **only** on an explicit user request in the current session — never inferred
from branch/PR state. Full definition, entry rule, and session scope are documented
in `.claude/skills/implement/SKILL.md`'s "Stacked Mode (opt-in)" section; this skill
follows the same rule rather than redefining it. In Normal Mode (the default), nothing
below changes.

## Pre-flight Checks (MANDATORY)

Before creating a PR, ALL of the following checks MUST pass:

### 1. Format Check

```bash
cargo fmt --all -- --check
```

If this fails, run `cargo fmt --all` to fix and commit the changes.

### 2. Clippy Check

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

**CRITICAL**: Zero warnings required. Fix all issues before proceeding.

### 3. Test Suite

```bash
cargo test --all
```

All tests must pass.

## Steps

**Note on `$BASE_BRANCH`**: Steps 1, 4, 4.5, 4.6, and 6 below all diff or target
against `$BASE_BRANCH`, determined by Step 3's logic (`develop`/`main` in Normal
Mode, or the sibling stack branch in Stacked Mode). If `/pr` was invoked by
`/implement` Step 6, the base branch is already supplied — use it immediately. If
invoked standalone, resolve `$BASE_BRANCH` per Step 3 before running Step 1's checks
below, so the WIRE Annotation Notice diffs the correct range from the start.

### Step 1: Run Pre-flight Checks

Execute all three checks above. If any fail:

1. Fix the issues
2. Commit the fixes using `/commit` skill
3. Re-run the checks until all pass

#### WIRE Annotation Notice (informational — does not block)

```bash
git diff "$BASE_BRANCH"...HEAD | grep -E '^\+.*WIRE\(#[0-9]+\)' | grep -v '^+++'
```

If the output is non-empty, print:

> ⚠️ This PR introduces WIRE(#N) annotation(s). Verify that Issue #N is open and
> will consume these items. The annotation will be auto-detected by /implement Step 4.0
> when Issue #N is implemented.

This check is informational only and does not block PR creation.

### Step 2: Verify Branch Status

```bash
# Check current branch
git branch --show-current

# Check if up to date with remote
git status
```

Verify:

- [ ] Not on `main` branch (direct commits to main are forbidden)
- [ ] Branch follows naming convention:
  - `feature/<issue-number>-<description>` for features
  - `bugfix/<issue-number>-<description>` for bug fixes
  - `hotfix/<issue-number>-<description>` for hotfixes
  - `docs/<issue-number>-<description>` for documentation
  - `refactor/<issue-number>-<description>` for refactoring

### Step 3: Determine Base Branch

**CRITICAL**: This project uses `develop` as the integration branch.

#### Normal Mode (default)

| Branch Type | Base Branch |
|-------------|-------------|
| feature/*   | `develop`   |
| bugfix/*    | `develop`   |
| docs/*      | `develop`   |
| refactor/*  | `develop`   |
| hotfix/*    | `main`      |
| release/*   | `main`      |

#### Stacked Mode (opt-in)

| Branch Type | Base Branch |
|-------------|-------------|
| any `feature/*` / `bugfix/*` / `docs/*` / `refactor/*` **in Stacked Mode** | the still-open sibling PR's branch recorded by `/implement` Step 3 |

The base branch is whatever `/implement` Step 3 recorded and passed through Step 6
(see that skill's "Stack position:" line). If `/pr` is invoked **standalone** in
Stacked Mode with no base supplied, **ask the user** which open PR branch to stack
on — offer the candidates from `gh pr list --state open --json number,headRefName,baseRefName,url`,
with `develop` (Normal Mode) as the safe default. **Never infer it.**

Set `$BASE_BRANCH` from whichever row above applies; Steps 1, 4, 4.5, 4.6, and 6 use
this variable.

**Branch Creation Rule**: In Normal Mode, create new branches from `origin/develop`:

```bash
git fetch origin
git checkout -b feature/<issue>-<desc> origin/develop
```

In Stacked Mode, see `.claude/skills/implement/SKILL.md` Step 3's branch-base
decision table instead.

### Step 4: Review Changes

```bash
# See all commits that will be in the PR
git log "$BASE_BRANCH"..HEAD --oneline

# See the diff
git diff "$BASE_BRANCH"...HEAD
```

### Step 4.5: CHANGELOG Gate (MANDATORY)

**Skip this step entirely** when the current branch prefix is one of:
`refactor/`, `ci/`, `test/`, `chore/`, `docs/`

Detect via:
```bash
git branch --show-current
```

If the prefix is unrecognized or not in the skip list, **do not skip** (fail-closed).

**For all other branch types** (`feature/`, `bugfix/`, `hotfix/`, `security/`):

#### 1. Check if CHANGELOG.md was updated on this branch

```bash
# $BASE_BRANCH already resolves to develop/main (Normal Mode) or the sibling stack
# branch (Stacked Mode) per Step 3
git diff "$BASE_BRANCH"...HEAD -- CHANGELOG.md
```

If this diff is **non-empty**, CHANGELOG.md was updated — gate passes. Proceed to Step 5.

#### 2. If CHANGELOG.md was NOT updated, detect user-facing changes

Check for user-facing changes in the diff:

```bash
# New CLI flags (additions of #[arg( or #[clap( lines)
git diff "$BASE_BRANCH"...HEAD -G'#\[arg\(|#\[clap\(' -- 'src/cli/'

# Changes to core behavior (application, formatters, config)
git diff "$BASE_BRANCH"...HEAD --stat -- src/sbom_generation/ src/application/ src/adapters/outbound/formatters/ src/cli/config_resolver.rs src/config.rs
```

Also consider:
- Branch prefix `bugfix/` or `hotfix/` → always treat as user-facing (bug fix)
- Branch prefix `security/` or label `security` → always treat as user-facing (security fix)

#### 3. Decision

| User-facing changes? | CHANGELOG updated? | Action |
|---|---|---|
| No | No | ✅ Gate passes — internal-only PR |
| No | Yes | ✅ Gate passes |
| Yes | Yes | ✅ Gate passes |
| Yes | No | ❌ **STOP** — prompt user |

If user-facing changes are detected and CHANGELOG.md was **not** updated, output:

> ⚠️ User-facing changes detected but `CHANGELOG.md [Unreleased]` was not updated on this branch.
>
> Please add an entry under the appropriate section before pushing:
> - `### Added` — new features or CLI flags
> - `### Fixed` — bug fixes
> - `### Security` — security fixes
> - `### Changed` — behavior changes
>
> Update `CHANGELOG.md`, commit the change, then re-run `/pr`.
> Type **yes** to proceed anyway (only if this PR is truly internal), or **no** to abort.

- **yes**: proceed but add a note in the PR body: `⚠️ CHANGELOG not updated — author confirmed internal-only.`
- **no** (or no response): **STOP**. Do not push or create the PR.

> **Note**: This gate complements `/release` Step 3.6 — catching missing entries at PR
> time prevents the empty `[Unreleased]` scenario that caused the v2.2.0 incident (Issue #491).

### Step 4.6: CLI Flag Documentation Backstop (conditional)

**Trigger**: Run this gate if the current branch added, removed, or renamed
any CLI flag (i.e., any `#[arg(` or `#[clap(` annotation was added/changed in `src/cli/`).

Detect via:
```bash
git diff "$BASE_BRANCH"...HEAD -G'#\[arg\(|#\[clap\(' -- 'src/cli/'
```

If the diff is **non-empty**, verify ALL of the following before proceeding to Step 5:

#### A. README.md usage section

- [ ] A new `###` subsection exists for the feature (or an existing section is updated)
- [ ] At least one ` ```bash ` command example demonstrates the new flag
- [ ] The Config File Schema Reference table includes the corresponding config key(s)
- [ ] The Priority and Merge Rules section is updated if the resolution order changed

#### B. README-JP.md

- [ ] All changes from A are translated into Japanese and applied

#### C. Example project config file

- [ ] `examples/sample-project/config/uv-sbom.config.yml` includes the new config key
  (commented out with the default value, matching the style of existing entries)

#### D. Example project documentation

- [ ] At least one example project README demonstrates the new flag

**If any checkbox is unchecked**, output:

> ⚠️ CLI documentation gap detected. The following items are missing for the new
> flag `--<flag-name>`:
>
> - [ ] README.md usage section
> - [ ] README-JP.md (Japanese translation)
> - [ ] Example config file entry
> - [ ] Example project README
>
> Please update the missing documentation and commit the changes before creating the PR.
> Type **yes** to proceed anyway (only if all gaps are intentionally deferred with a
> tracking Issue linked in the PR body), or **no** to abort.

- **yes** (with tracking Issues linked): Proceed, add a note to PR body listing the deferred Issues.
- **no** (or no response): **STOP**. Do not push or create the PR.

**Do NOT skip this gate** even if the implementation plan did not list documentation files.

### Relationship to /implement Step 4.3

| | `/implement` Step 4.3 | `/pr` Step 4.6 |
|---|---|---|
| When it runs | During implementation, before code review | Before PR creation |
| Purpose | Catch gaps early, prompt immediate fix | Backstop if Step 4.3 was skipped or incomplete |
| On failure | Fix now, continue | Block or defer with linked Issue |

### Step 5: Push to Remote

```bash
git push -u origin $(git branch --show-current)
```

### Step 6: Create Pull Request

`$BASE_BRANCH` is the value determined in Step 3 (`develop`/`main` in Normal Mode,
or the sibling stack branch in Stacked Mode). Use the following template:

```bash
# $BASE_BRANCH is already set from Step 3 — do not hardcode it here, even in Normal Mode
gh pr create --base "$BASE_BRANCH" --title "TITLE" --body "$(cat <<'EOF'
## Summary
[1-3 bullet points summarizing the changes]

## Related Issue
Closes #XX

## Changes Made
- [Change 1]
- [Change 2]
- [Change 3]

## Test Plan
- [ ] `cargo test --all` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] Manual testing performed (if applicable)

## Screenshots (if applicable)
[Add screenshots for UI changes]

---
Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Stacked PR note (only when `$BASE_BRANCH` is not `develop`/`main`)**: insert an
additional section between `## Related Issue` and `## Changes Made`:

```markdown
## Stacked PR
This PR is stacked on top of #<lower PR number> (`<lower branch>`) and targets that
branch rather than `develop`. Its diff therefore excludes changes already under
review in #<lower PR number>. GitHub will retarget this PR to `develop`
automatically once #<lower PR number> merges.
```

Omit this section entirely in Normal Mode. Because the body heredoc above is quoted
(`<<'EOF'`), `$BASE_BRANCH` does **not** expand inside it — write the lower PR
number and branch name literally when composing the body, not as a shell variable.

### Step 7: Verify PR Creation

After creation:

1. Output the PR URL
2. Verify CI is running: `gh pr checks`
3. Report status to user

## Merging a Stacked PR (Stacked Mode only)

### Who merges

**Claude does not merge PRs into `develop`/`main` on its own judgment — neither via
`gh pr merge` nor via the asynchronous merge REST API below.** `/pr` creates and
stacks PRs and reports readiness (CI status, mergeability); the user reviews and
merges. A green CI status is not, by itself, authorization to merge.

If the user explicitly asks Claude to perform a merge, that authorizes **that one
PR only** — it is never standing permission for the rest of the stack or for future
sessions. Ask again (or wait) at each subsequent mergeable PR in the stack. This
section is reference documentation for the user's own merge workflow, and for that
narrow explicitly-requested case.

### Verifying CI on an interior stack layer

This project's CI workflow (`.github/workflows/ci.yml`) filters its `pull_request`
trigger to `branches: [main, develop]`. A stacked PR based on a sibling branch
(not `develop`/`main`) will therefore show **"no checks reported"** in
`gh pr checks`, even though the `push` trigger still ran CI on the branch itself.
Verify with the branch's own runs instead:

```bash
gh run list --branch <branch-name>
gh run view <run-id> --json status,conclusion,jobs
```

### Merge procedure

1. Try the normal path first:
   ```bash
   gh pr merge <number> --merge
   ```
2. A PR that is part of a stack is refused with an error to the effect of:
   > This pull request is part of a stack and must be merged using the
   > asynchronous merge REST API.
3. Fall back to GitHub's asynchronous merge REST API:
   ```bash
   gh api --method PUT repos/{owner}/{repo}/pulls/{number}/merge-async -f merge_method=merge
   ```
   This is a **public-preview** endpoint — confirm the current request/response
   shape live via `gh api` before relying on it, rather than trusting any prior
   transcript or this document, since preview APIs may still be in flux.
4. Poll the returned job/status identifier until the merge settles (`merged` or
   `failed`):
   ```bash
   gh api repos/{owner}/{repo}/pulls/{number}/merge-async/{uuid}
   ```
   Do not consider the PR merged until this returns a terminal status.

### Post-merge verification of the next stack member

After the bottom PR of a stack merges, GitHub automatically rebases the next PR in
the stack to target `develop` directly. **Verify this happened — do not assume it**:

```bash
gh pr view <next-pr> --json baseRefName
```

Once its base is `develop` again, its CI re-triggers normally via the
`pull_request` trigger.

### Known limitations

- Auto-merge is not supported for stacked PRs.
- GitHub Desktop does not support stacks.
- All stack members must live in the same repository (no cross-fork stacks).

## Error Handling

### Pre-flight Check Failures

If any pre-flight check fails:

1. **Format failure**: Run `cargo fmt --all`, commit, retry
2. **Clippy failure**: Fix warnings, commit, retry
3. **Test failure**: Fix tests, commit, retry

**NEVER** create a PR if pre-flight checks fail.

### Push Failures

If push fails:

1. Check if branch exists on remote
2. Check for conflicting changes
3. Pull and resolve conflicts if needed

### PR Creation Failures

If `gh pr create` fails:

1. Check authentication: `gh auth status`
2. Check if PR already exists: `gh pr list`
3. Report error details to user

## Example Usage

User: "PRを作成して"

Claude executes /pr skill:

1. Runs `cargo fmt --all -- --check` (passes)
2. Runs `cargo clippy --all-targets --all-features -- -D warnings` (passes)
3. Runs `cargo test --all` (passes)
4. Verifies branch is `feature/84-agent-skills`
5. Determines base branch is `develop`
6. Pushes to remote
7. Creates PR with English title and body (base: develop)
8. Reports PR URL to user
