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

### Step 1: Run Pre-flight Checks

Execute all three checks above. If any fail:

1. Fix the issues
2. Commit the fixes using `/commit` skill
3. Re-run the checks until all pass

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

| Branch Type | Base Branch |
|-------------|-------------|
| feature/*   | `develop`   |
| bugfix/*    | `develop`   |
| docs/*      | `develop`   |
| refactor/*  | `develop`   |
| hotfix/*    | `main`      |
| release/*   | `main`      |

**Branch Creation Rule**: Always create new branches from `origin/develop`:

```bash
git fetch origin
git checkout -b feature/<issue>-<desc> origin/develop
```

### Step 4: Review Changes

```bash
# See all commits that will be in the PR
git log origin/develop..HEAD --oneline

# See the diff
git diff origin/develop...HEAD
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
# For feature/bugfix/refactor branches (base: develop)
git diff origin/develop...HEAD -- CHANGELOG.md

# For hotfix/* branches (base: main)
git diff origin/main...HEAD -- CHANGELOG.md
```

If this diff is **non-empty**, CHANGELOG.md was updated — gate passes. Proceed to Step 5.

#### 2. If CHANGELOG.md was NOT updated, detect user-facing changes

Check for user-facing changes in the diff:

```bash
# New CLI flags (additions of #[arg( or #[clap( lines)
git diff origin/develop...HEAD -G'#\[arg\(|#\[clap\(' -- 'src/cli/'

# Changes to core behavior (application, formatters, config)
git diff origin/develop...HEAD --stat -- src/sbom_generation/ src/application/ src/adapters/outbound/formatters/ src/cli/config_resolver.rs src/config.rs
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

### Step 5: Push to Remote

```bash
git push -u origin $(git branch --show-current)
```

### Step 6: Create Pull Request

Use the following template:

```bash
gh pr create --base develop --title "TITLE" --body "$(cat <<'EOF'
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

### Step 7: Verify PR Creation

After creation:

1. Output the PR URL
2. Verify CI is running: `gh pr checks`
3. Report status to user

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
