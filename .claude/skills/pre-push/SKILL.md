---
name: pre-push
description: Run all validations before pushing to remote
---

# /pre-push - Pre-push Validation Skill

Final validation before pushing commits to remote repository.

## Purpose

Validate branch conventions and push commits to remote. Quality checks (fmt, clippy, tests)
are delegated to the `.githooks/pre-push` hook, which runs automatically when `git push` executes.

> **Hook delegation**: `.githooks/pre-push` runs the canonical fmt / clippy / test block
> (see `.claude/conventions/ci-checks.md`) on every `git push`.
> Run `make setup` once to activate the hook if you haven't already.

## Validation Checklist

All of the following MUST pass before pushing:

### 1. Branch Naming Convention

```bash
git branch --show-current
```

Verify the branch name follows `.claude/conventions/branching.md` → "Branch Naming
(label → prefix)" (read it if unsure which prefix the Issue's labels map to).

**FORBIDDEN branches for direct push:**

- `main` - Use PR only
- `develop` - Use PR only (if applicable)

### 2. Remote Branch Target

```bash
git remote -v
git branch -vv
```

Verify:

- [ ] Pushing to correct remote (typically `origin`)
- [ ] Not accidentally pushing to upstream/fork

## Steps

### Step 1: Check Branch Name

```bash
BRANCH=$(git branch --show-current)
echo "Current branch: $BRANCH"
```

Verify:

- [ ] Matches naming convention
- [ ] Not on `main` or `develop`
- [ ] Issue number in branch name (if applicable)

### Step 2: Verify Unpushed Commits

```bash
git log origin/$(git branch --show-current)..HEAD --oneline 2>/dev/null || git log --oneline -5
```

Review what will be pushed.

### Step 3: Final Confirmation

Before pushing, confirm:

- [ ] Branch name is correct
- [ ] Commits are reviewed
- [ ] `.githooks/pre-push` hook is active (`make setup` has been run)

### Step 4: Push

```bash
git push -u origin $(git branch --show-current)
```

The `.githooks/pre-push` hook will automatically run the canonical check block
(`.claude/conventions/ci-checks.md`) before the push completes.

## Error Handling

### Hook Failures (fmt / clippy / test)

If the `.githooks/pre-push` hook reports a failure:

1. Read the hook output to identify which check failed
2. Fix the issue (format error, clippy warning, or test failure)
3. Commit the fix
4. Re-run `/pre-push`

### Wrong Branch

```
WARNING: You are on branch 'main'. Direct pushes to main are not allowed.
```

**CRITICAL**: Never push to `main`/`develop`. Instead:

1. Create a feature branch per `.claude/conventions/branching.md` → "Branch Base"
   (Normal Mode: from `origin/develop`, never `main`; Stacked Mode only on an explicit
   user request — never inferred)
2. Push the feature branch
3. Create a PR via the `/pr` skill, which resolves the target branch into
   `$BASE_BRANCH`

### Hook Not Active

If the hook does not run (no `[pre-push]` output during push):

```bash
make setup
```

Then re-run the push.

## Example Usage

User: "pushする前にチェックして"

Claude executes /pre-push skill:

1. Checks branch: `feature/84-agent-skills` - VALID
2. Reviews unpushed commits
3. Reports: "Branch and commits look good. Pushing now (hook will run quality checks)."
4. Executes `git push -u origin feature/84-agent-skills`
5. `.githooks/pre-push` runs fmt/clippy/test automatically

## Summary Output

After push completes successfully, output:

```
Pre-push Complete
=================
[PASS] Branch: feature/84-agent-skills (valid naming)
[PASS] Hook: cargo fmt, clippy, tests passed
[INFO] Commits pushed: X commits

Pushed to origin/feature/84-agent-skills
```
