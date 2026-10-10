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

### 3. Draft Issue from Template

Use the template under `## Issue Structure Template` in `.claude/issue-guidelines.md`
for Feature Requests. Use the template under `### Bug Report Template` in
`.claude/issue-guidelines.md` for Bug Reports.

Follow the formatting rules under `## Issue Structure Template` in
`.claude/issue-guidelines.md` — in particular, leave a blank line after `<summary>`
and before `</details>`.

Do not include implementation code in either section — see "No Implementation Code
in Issue Bodies" in `.claude/issue-guidelines.md` for the four allowed exceptions.

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

Use the labels listed under `## Labels Reference` in `.claude/issue-guidelines.md`.

## Example Usage

User: "バグ報告したい。cargo run で --no-network オプションが効かない"

Claude executes /issue skill:

1. Gathers details about the bug
2. Creates English Issue with proper template
3. Adds `bug` label
4. Creates Issue using `gh issue create`
5. Reports Issue URL to user
