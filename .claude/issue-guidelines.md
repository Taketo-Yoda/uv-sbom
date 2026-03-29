# GitHub Issue Creation Guidelines

This file contains the authoritative guidelines for creating GitHub Issues in this project.
It is referenced by the `/issue` skill during Issue drafting.

## Purpose

Issues serve as the foundation for development work in this project. Well-written issues enable:
- AI agents to implement features autonomously
- Clear communication of requirements and technical specifications
- Consistent documentation of decisions and rationale

## Key Principles

1. **Language**: Always write issues in **English**
   - Applies to: Issue title, description, code examples, acceptance criteria
   - No exceptions

2. **AI-First Design**: Issues must contain sufficient detail for autonomous AI implementation
   - Include technical specifications, not just high-level descriptions
   - Provide concrete code examples and file paths
   - Document design decisions and rationale explicitly
   - Anticipate implementation questions and address them proactively

3. **Completeness**: An issue should answer "Can an AI implement this without asking for clarification?"
   - If the answer is no, add more detail

## Issue Structure Template

Use this structure for all issues:

```markdown
## Summary
[Brief description of the feature or problem]
[Explain why this is needed and what value it provides]

## Problem / Current Situation
[Explain current behavior or implementation]
[Provide context that helps understand the need]
[Reference related code, issues, or documentation]

## Proposed Solution / Technical Details
[Detailed technical specification]
[Architecture considerations]
[Design decisions and trade-offs]
[Security implications (if any)]

## Implementation Examples

### Example 1: [Specific file or component]
```[language]
[Concrete code example or documentation snippet]
```
[Explanation of the example]
[Why this approach was chosen]

### Example 2: [Another file or component]
```[language]
[Another concrete example]
```

## Acceptance Criteria
- [ ] [Specific, testable criterion 1]
- [ ] [Specific, testable criterion 2]
- [ ] All existing tests pass
- [ ] New tests added for new functionality (if applicable)
- [ ] Documentation updated (if applicable)
- [ ] Code formatted with `cargo fmt --all`
- [ ] Clippy warnings resolved (`cargo clippy -- -D warnings`)

## Files to Update/Create
1. `path/to/file1.rs` — [What changes are needed]
2. `path/to/file2.md` — [What changes are needed]
3. `path/to/new_file.rs` — [What to create and why]

## Additional Notes
[Any other relevant information]
[Links to related issues or PRs]
[Dependencies or blockers]
```

## Issue Types

### Feature Request Template

```markdown
## Summary
[Brief description of the feature]

## Problem
[What problem does this solve?]

## Proposed Solution
[How should this be implemented?]

## Technical Implementation
- Files to modify:
- New files to create:
- Dependencies:
- Architecture considerations:

## Acceptance Criteria
- [ ] [Specific, testable criterion]
- [ ] Tests added
- [ ] Documentation updated (if applicable)
```

### Bug Report Template

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

## Writing for AI Implementation

1. **Provide Concrete Examples** — Show it, don't just describe it. Use actual code, not pseudocode.
2. **Include File Paths** — Specify exact paths: `src/sbom_generation/services/package_filter.rs`
3. **Specify Design Decisions Explicitly** — "Use Strategy pattern" not "Improve the design"
4. **Document Assumptions and Constraints** — Security, performance, backward compatibility
5. **Provide Context** — Reference related code, issues, or architectural patterns

## Pre-Submission Verification (MANDATORY)

Before submitting via `gh issue create`:

```
- [ ] VERIFY: Entire issue content is in English (title and body)
- [ ] CHECK: All template sections are present
- [ ] VERIFY: Code examples use proper markdown formatting
- [ ] CHECK: Acceptance criteria use checklist format
- [ ] VERIFY: File paths are specific and accurate
- [ ] FINAL: Re-read the full issue as if you were an AI implementing it
```

**Why this checklist is necessary**:
- Catches language violations before submission (Incident: PR #121 — Issue created in Japanese)
- Creates a moment for reflection and review
- Prevents the need to edit issues after creation

## Quality Checklist

- [ ] **Pre-Submission Verification completed** ⚠️
- [ ] Issue written in English (title and body)
- [ ] Clear description of problem/feature with context
- [ ] Technical details sufficient for implementation
- [ ] At least one concrete code example provided
- [ ] Acceptance criteria in checklist format (testable)
- [ ] Files to update/create are listed with explanations
- [ ] Design decisions documented with rationale
- [ ] Question: "Can an AI implement this without asking questions?" — Answer: Yes

## Examples of Good Issues

**Example 1: Feature Request (Issue #23)**
✅ Clear description, technical hints, example scenarios, message format specified, output channel specified.

**Example 2: Documentation (Issue #32)**
✅ Documents existing behavior, specific examples for each file, code snippets, clear acceptance criteria, security rationale.

**Example 3: Guidelines Issue (Issue #33)**
✅ Comprehensive template structure, multiple concrete examples, quality checklist, references to existing good issues.

## Examples of Issues to Avoid

| ❌ Bad Example | Problems |
|----------------|----------|
| Title: "Fix bug" / Body: "doesn't work right" | No reproduction steps, no expected behavior, impossible for AI to implement |
| Title: "Add logging" / Body: "We should add logging" | No log levels, no framework, no file paths, no examples |
| Title: "Improve performance" / Body: "Make it faster" | No baseline metrics, no target, no bottlenecks identified |
| Title: "Add security validation" / Body: "Add validation to file ops" | No code examples, no specific files, no threat model |

## Integration with Development Workflow

1. **Issue Creation** → Discussion/Review → Implementation → PR → Review → Merge
2. Always reference the issue number in commits: `feat: add feature X (#123)`
3. Use `Closes #123` in PR description to auto-close issues
4. Update issues with implementation notes if approach changes during implementation

## Maintaining Issue Quality

- Review existing issues periodically for quality
- Close outdated or duplicate issues
- Add labels to categorize issues (bug, enhancement, documentation, security, etc.)

## Labels Reference

| Label | Purpose |
|-------|---------|
| `bug` | Bug fixes |
| `enhancement` | New features or improvements |
| `documentation` | Documentation updates |
| `refactor` | Code refactoring |
| `security` | Security-related issues |
| `performance` | Performance improvements |
| `testing` | Test additions or improvements |
