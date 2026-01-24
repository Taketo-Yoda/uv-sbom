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
