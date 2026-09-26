---
name: issue
description: Create GitHub Issues with consistent formatting for autonomous implementation
---

# /issue - Issue Creation Skill

Create GitHub Issues with consistent formatting and sufficient technical detail for autonomous implementation.

## Language Requirement

**IMPORTANT**: All GitHub Issues MUST be written in **English**.

- Issue title: English
- Issue body: English
- Labels: English
- Comments: English

## Steps

### 1. Read Issue Guidelines (MANDATORY)

Before drafting any Issue content, read:

- **`.claude/issue-guidelines.md`** — full Issue creation guidelines, templates, and quality checklist

This file contains the authoritative structure, Pre-Submission Verification checklist, and examples of good/bad Issues.

### 2. Gather Information

After reading the guidelines, gather the following information from the user:

- **Type**: Feature, Bug, Documentation, Refactor, or other
- **Summary**: Brief description of the task
- **Context**: Why is this needed?
- **Technical Details**: Implementation hints if available (file paths, precedent
  Issues/PRs, invariants) — these go in the collapsed AI section
- **Types affected**: New or changed types, if any — these become the `## Design Sketch`
  Mermaid diagram. If no types change, the Design Sketch section is omitted.

### 3. Determine Issue Template

Both templates split into a visible **human section** and a collapsed **AI section**.
These mirror `.claude/issue-guidelines.md` — if the two ever disagree, the guidelines
file wins and this skill must be corrected.

**Formatting rule**: leave a blank line after `<summary>` and before `</details>`, or
GitHub renders the AI section as literal text.

**No implementation code** in either section — see "No Implementation Code in Issue
Bodies" in the guidelines for the four allowed exceptions.

Based on the type, use the appropriate structure:

#### Feature Request

```markdown
## Summary
[2–3 sentences: what changes and what value it provides. No implementation detail.]

## Why
- [Reason / pain point 1]
- [Reason / pain point 2]

## Design Sketch
[Minimal Mermaid classDiagram of NEW or CHANGED types only. Omit entirely if no
types change.]

## Scope
**In**
- [What this Issue delivers]

**Out**
- [Explicitly excluded]

## Acceptance Criteria
- [ ] [Behavior-level, human-verifiable outcome]

<details>
<summary>🤖 Implementation Spec (for AI agents)</summary>

## Context & Constraints
- [Existing pattern, precedent Issue/PR, invariant, or file not to touch]

## Design Decisions
- **[Decision]** — [rationale, in prose]

## Files to Update/Create
1. `path/to/file.rs` — [what changes]

## Technical Acceptance Criteria
- [ ] All existing tests pass (`cargo test --all`)
- [ ] New tests added for new functionality (if applicable)
- [ ] Formatted with `cargo fmt --all`
- [ ] No new Clippy warnings (`cargo clippy --all-targets --all-features -- -D warnings`)
- [ ] Documentation updated (if applicable)
- [ ] No speculative `#[allow(dead_code)]` (see `.claude/CLAUDE.md` → Dead Code Policy)

</details>
```

#### Bug Report

```markdown
## Summary
[1–2 sentences: what is broken and who it affects.]

## Current Behavior
[What happens now. A reproduction command and its real error output are allowed here.]

## Expected Behavior
[What should happen instead.]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Acceptance Criteria
- [ ] [Observable behavior after the fix]
- [ ] The reproduction above no longer triggers the failure

<details>
<summary>🤖 Implementation Spec (for AI agents)</summary>

## Root Cause Analysis
- Environment: [OS, Rust version, etc.]
- [Which file/function is responsible and why, citing `path/to/file.rs:LINE`]

## Proposed Fix
[Technical approach to fix, in prose — no implementation code]

## Files to Update/Create
1. `path/to/file.rs` — [what changes]

## Technical Acceptance Criteria
- [ ] Regression test added to prevent recurrence
- [ ] All existing tests pass (`cargo test --all`)
- [ ] Formatted with `cargo fmt --all`
- [ ] No new Clippy warnings (`cargo clippy --all-targets --all-features -- -D warnings`)

</details>
```

### 4. Validate Completeness

Before creating the Issue, verify:

- [ ] Title is concise and descriptive (in English)
- [ ] Technical detail is sufficient for autonomous implementation
- [ ] Acceptance Criteria are behavior-level and human-verifiable; CI/tooling checks live in Technical Acceptance Criteria
- [ ] Labels are appropriate (bug, enhancement, documentation, etc.)
- [ ] Related Issues/PRs are referenced if applicable
- [ ] Human section present and complete (Summary, Why, Scope, Acceptance Criteria;
      Design Sketch when types change)
- [ ] AI section wrapped in `<details><summary>🤖 Implementation Spec (for AI agents)</summary>`,
      with a blank line after `<summary>` and before `</details>`
- [ ] AI section contains Context & Constraints, Design Decisions, Files to Update/Create,
      Technical Acceptance Criteria
- [ ] No implementation code outside the allowed exceptions
- [ ] The human section alone conveys what and why in under a minute

### 5. Create the Issue

Use the `gh` CLI to create the Issue. The body contains HTML tags and backticks —
pass it via a quoted heredoc (or `--body-file`) so the shell does not mangle
`<details>` or fenced blocks:

```bash
gh issue create --title "TITLE" --label "LABEL" --body "$(cat <<'EOF'
<body>
EOF
)"
```

### 6. Confirm Creation

After creating, output:

- Issue URL
- Issue number
- Summary of what was created

## Labels Reference

Common labels for this project:

- `bug` - Bug fixes
- `enhancement` - New features or improvements
- `documentation` - Documentation updates
- `refactor` - Code refactoring
- `security` - Security-related issues
- `performance` - Performance improvements
- `testing` - Test additions or improvements

## Example Usage

User: "バグ報告したい。cargo run で --no-network オプションが効かない"

Claude executes /issue skill:

1. Gathers details about the bug
2. Creates English Issue with proper template
3. Adds `bug` label
4. Creates Issue using `gh issue create`
5. Reports Issue URL to user
