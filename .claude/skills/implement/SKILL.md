---
name: implement
description: Orchestrate complete issue implementation workflow from branch to PR
---

# /implement - Issue Implementation Skill

Orchestrates the complete workflow for implementing a GitHub issue, from branch creation to PR submission.

## Language Requirement

**IMPORTANT**: All outputs (commits, PRs) MUST be written in **English**.

## Workflow Overview

```
Issue Analysis → Branch Creation → Implementation → Commit → PR Creation
```

## Steps

### Step 1: Analyze Issue (MANDATORY)

```bash
gh issue view <issue-number>
```

Extract:
- Issue title and description
- Labels (to determine branch prefix)
- Acceptance criteria
- Files to modify

### Step 2: Determine Branch Name

Based on issue labels:

| Issue Label | Branch Prefix |
|-------------|---------------|
| `enhancement` | `feature/` |
| `bug` | `bugfix/` |
| `refactor` | `refactor/` |
| `documentation` | `docs/` |
| (no label) | `feature/` |

Format: `<prefix>/<issue-number>-<short-description>`

### Step 3: Create Feature Branch (MANDATORY)

```bash
# Verify not already on a feature branch for this issue
git branch --show-current

# If on develop or main, create new branch
git fetch origin
git checkout -b <branch-name> origin/develop
```

**CRITICAL**: This step cannot be skipped. If already on the correct feature branch, verify and continue.

### Step 4: Implement Changes

- Follow the issue's technical specifications
- Adhere to project architecture (see `.claude/instructions.md`)
- Add tests for new functionality
- Update documentation as needed

### Step 5: Commit Changes

Invoke `/commit` skill with:
- Reference to issue number in commit message
- Conventional commit format

### Step 6: Create Pull Request

Invoke `/pr` skill with:
- Base branch: `develop`
- Reference to issue: `Closes #<issue-number>`

### Step 7: Report Completion

Output:
- Branch name created
- Files modified
- Commit hash
- PR URL

## Error Handling

### Already on Feature Branch

If already on a feature branch:
1. Verify it matches the issue being implemented
2. If yes, continue from Step 4
3. If no, ask user for clarification

### Issue Not Found

If `gh issue view` fails:
1. Report error to user
2. Ask for correct issue number

### Branch Already Exists

If branch already exists:
1. Check if it's for the same issue
2. Offer to switch to existing branch or create new one

## Example Usage

User: "implement issue #96"

Claude executes /implement skill:
1. Reads issue #96 details
2. Determines label is "enhancement" → prefix "feature/"
3. Creates branch `feature/96-check-vulnerabilities-usecase`
4. Implements the changes per issue specification
5. Runs `/commit` skill
6. Runs `/pr` skill
7. Reports: "Created PR #XX for issue #96"
