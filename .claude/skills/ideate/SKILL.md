---
name: ideate
description: Orchestrate the complete feature ideation workflow from raw idea to GitHub Issue
---

# /ideate - Feature Ideation Skill

Orchestrates the complete workflow from a feature idea to a fully-formed,
vision-aligned GitHub Issue ready for autonomous implementation.

## Language Requirement

**IMPORTANT**: All outputs (Issue title, body, comments) MUST be written in **English**.

## Workflow Overview

```
Raw Idea → Triage → Competitive Analysis → Technical Specification → Issue Creation
```

## Steps

### Step 1: Capture the Feature Idea (MANDATORY)

Ask the user (if not already provided):
- What problem does this feature solve?
- Who is the target user? (developer / security engineer / compliance reviewer)
- What should the output look like? (if it affects SBOM output)

Do NOT proceed to Step 2 until this information is captured.

### Step 2: Run Feature Triage (MANDATORY)

Read `.claude/feature-triage.md` and apply the 4-step checklist.

Output the triage result in this format:
```
Triage Result:
- Step 1 (Scope): PASS / STOP (reason: ...)
- Step 2 (Value): PASS (criteria: A/B/C) / FAIL
- Step 3 (Differentiation): D: yes/no, E: yes/no, F: yes/no
- Step 4 (Output Quality): PASS / FAIL
- Priority: HIGH / MEDIUM / LOW / OUT OF SCOPE
```

If triage result is OUT OF SCOPE or STOP: stop and explain why.
If triage result is PASS: continue to Step 3.

### Step 3: Competitive Analysis (MANDATORY for HIGH/MEDIUM priority)

For features that pass triage at HIGH or MEDIUM priority, briefly check:
1. Does cyclonedx-python, pip-audit, or Syft already offer this? (check `.claude/competitive-landscape.md` if it exists)
2. If yes: is our version differentiated enough? How?
3. If no: note this as a potential differentiator.

Include the competitive analysis finding in the Issue body.

### Step 4: Draft Technical Specification

Based on the feature idea, draft:
1. Which layer of the hexagonal architecture is affected?
   - Domain layer: `src/sbom_generation/`
   - Application layer: `src/application/`
   - Port trait: `src/ports/`
   - Adapter: `src/adapters/`
   - CLI: `src/cli/`
2. Which existing files need changes?
3. Which new files need to be created?
4. Are there any new port traits needed?
5. Are there test fixtures needed?

Reference `.claude/CLAUDE.md` Architecture Overview for architecture constraints.

### Step 5: Draft Acceptance Criteria

Write specific, testable acceptance criteria. Every criterion must be:
- Binary (pass/fail)
- Verifiable by running a command or reading output
- Specific enough that an AI agent can verify without human input

Standard criteria to always include:
- [ ] All existing tests pass (`cargo test --all`)
- [ ] No new Clippy warnings (`cargo clippy --all-targets --all-features -- -D warnings`)
- [ ] Formatted with `cargo fmt --all`
- [ ] New tests added for new functionality
- [ ] Documentation updated (if user-facing change)

### Step 6: Create GitHub Issue

Invoke the `/issue` skill with the complete draft.

The Issue body MUST include:
1. Feature Triage Result (from Step 2)
2. Competitive Analysis finding (from Step 3)
3. Technical implementation details (from Step 4)
4. Acceptance criteria (from Step 5)
5. Files to update/create

### Step 7: Report Completion

Output:
- Issue URL and number
- Triage result summary
- Priority recommendation
- Suggested next step (e.g., "Run /implement #<issue-number> to start implementation")

## Error Handling

### Feature fails triage

If the feature fails triage:
1. Report the specific STOP condition
2. Suggest an alternative approach or tool if applicable
3. Ask the user if they want to reconsider the scope

### Ambiguous feature description

If the feature description is too vague to draft a technical specification:
1. Ask ONE clarifying question (the most important missing piece)
2. Do not ask multiple questions at once
3. Once answered, continue the workflow

## Example Usage

User: "I want to add a feature to show which dependency version introduced a CVE"

Claude executes /ideate:
1. Captures: affects Markdown output, target: security engineers, shows root-cause transitive dep
2. Triage: PASS (Step 1: uses uv.lock graph; Step 2: criterion B; Step 3: E=yes, F=yes)
3. Competitive: none of the competitors show root-cause transitive CVE attribution
4. Technical: affects markdown_formatter.rs, vulnerability_view.rs, needs graph traversal in domain layer
5. Drafts acceptance criteria with specific output format
6. Creates Issue #XXX via /issue skill
7. Reports: "Created Issue #XXX (HIGH priority). Run /implement #XXX to start."
