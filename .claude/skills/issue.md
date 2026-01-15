# /issue - Issue Creation Skill

Create GitHub Issues with consistent formatting and sufficient technical detail for autonomous implementation.

## Language Requirement

**IMPORTANT**: All GitHub Issues MUST be written in **English**.

- Issue title: English
- Issue body: English
- Labels: English
- Comments: English

## Steps

### 1. Gather Information

Before creating an Issue, gather the following information from the user:

- **Type**: Feature, Bug, Documentation, Refactor, or other
- **Summary**: Brief description of the task
- **Context**: Why is this needed?
- **Technical Details**: Implementation hints if available

### 2. Determine Issue Template

Based on the type, use the appropriate structure:

#### Feature Request

```markdown
## Summary
[Brief description of the feature]

## Problem
[What problem does this solve?]

## Proposed Solution
[How should this be implemented?]

## Technical Implementation
[Technical details for autonomous implementation]
- Files to modify:
- New files to create:
- Dependencies:
- Architecture considerations:

## Acceptance Criteria
- [ ] [Specific, testable criterion]
- [ ] [Another criterion]
- [ ] Tests added
- [ ] Documentation updated (if applicable)
```

#### Bug Report

```markdown
## Summary
[Brief description of the bug]

## Current Behavior
[What happens now?]

## Expected Behavior
[What should happen?]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Technical Details
- Environment: [OS, Rust version, etc.]
- Error messages:
- Related files:

## Proposed Fix
[Technical approach to fix]

## Acceptance Criteria
- [ ] Bug is fixed
- [ ] Tests added to prevent regression
- [ ] No new warnings from clippy
```

### 3. Validate Completeness

Before creating the Issue, verify:

- [ ] Title is concise and descriptive (in English)
- [ ] Technical detail is sufficient for autonomous implementation
- [ ] Acceptance criteria are specific and testable
- [ ] Labels are appropriate (bug, enhancement, documentation, etc.)
- [ ] Related Issues/PRs are referenced if applicable

### 4. Create the Issue

Use the `gh` CLI to create the Issue:

```bash
gh issue create --title "TITLE" --body "BODY" --label "LABEL"
```

### 5. Confirm Creation

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
