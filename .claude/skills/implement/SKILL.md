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
Issue Analysis → Branch Creation → [Planning] → Implementation → Commit → PR Creation
                                        ↑ Opus        ↑ Sonnet
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

### Step 3.5: Implementation Planning (MANDATORY)

Spawn the Architect agent using the Opus model with the issue description and
relevant existing code as context:

```
Agent({
  subagent_type: "architect",
  model: "opus",
  prompt: <issue description> + <relevant existing code context>
})
```

Gather relevant existing code context by:
- Reading files listed in the issue's "Files to Update / Modify" section
- Reading adjacent modules or traits that the new code must implement or extend
- Running `git grep` for key symbols mentioned in the issue

The Architect agent produces an implementation plan covering:

| Plan Section | Content |
|-------------|---------|
| Files to modify | Path + reason for each file |
| Files to create | Path + module role + which layer (domain / application / adapter / port) |
| Interface design | New traits, structs, enums with their signatures |
| Implementation order | Step-by-step sequence with rationale |
| Risk flags | Potential layer boundary violations, DDD concerns, edge cases |

**Present the plan to the user and wait for explicit confirmation before
proceeding to Step 4. Do not modify any files until the user confirms.**

Accepted responses:
- "Looks good, proceed" → continue to Step 4
- "Adjust X" → revise plan, re-present
- "Cancel" → halt

### Step 4: Implement Changes

- **Follow the confirmed plan from Step 3.5 exactly**
- If an unexpected situation arises that requires deviating from the plan,
  **pause and report to the user before proceeding**
- Adhere to project architecture (see `.claude/CLAUDE.md`)
- Add tests for new functionality
- Update documentation as needed
- **i18n**: Every new user-visible string output via `eprintln!` or `println!`
  MUST be added as a named key in both `EN_MESSAGES` and `JA_MESSAGES` in
  `src/i18n/mod.rs`. Never hardcode English text in output paths.

### Step 4.5: Code Review (MANDATORY)

Invoke `/code-review` skill.

- The skill runs a Reviewer Agent against the current `git diff HEAD`.
- If the review **PASSES**, proceed to Step 5.
- If the review **FAILS** after the maximum iteration limit (3), halt and report
  remaining issues to the user. Do **NOT** invoke `/commit` until `/code-review`
  returns PASS.

### Step 5: Commit Changes

Invoke `/commit` skill with:
- Reference to issue number in commit message
- Conventional commit format

### Step 6: Create Pull Request

Invoke `/pr` skill with:
- Base branch: `develop`
- Reference to issue: `Closes #<issue-number>`

### Step 7: Update Architecture Overview (conditional)

After implementation is complete, evaluate whether the changes affected the project architecture:

**Update `.claude/CLAUDE.md` → `## Architecture Overview` if any of the following changed:**
- A new module or subdirectory was added/removed under `src/`
- A key type was renamed, added, or removed
- A new invariant or constraint was introduced
- The config resolution order or config struct changed

**Skip this step if:**
- The change was purely internal (renamed a private function, fixed a bug, adjusted formatting)
- No module boundaries, public APIs, or key types were affected

When updating, keep descriptions concise. Do **not** include function signatures, argument lists, or file-level details — only module-level roles, key public types, and design constraints.

### Step 8: Report Completion

Output:
- Branch name created
- Files modified
- Commit hash
- PR URL

## Error Handling

### Already on Feature Branch

If already on a feature branch:
1. Verify it matches the issue being implemented
2. If yes, continue from Step 3.5
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
4. Spawns Architect agent (Opus), presents implementation plan, awaits user confirmation
5. Implements the changes following the confirmed plan
6. Runs `/commit` skill
7. Runs `/pr` skill
8. Reports: "Created PR #XX for issue #96"
