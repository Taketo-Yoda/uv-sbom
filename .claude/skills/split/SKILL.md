---
name: split
description: Decompose a large GitHub Issue (epic, refactor, or feature) into subtask Issues, each small enough for a single focused PR
---

# /split - Issue Decomposition Skill

Decomposes a large GitHub Issue into subtask Issues, each implementable autonomously in a single PR.

## Language Requirement

**IMPORTANT**: All created GitHub Issues MUST be written in **English**.

## Workflow Overview

```
Read Parent Issue → Propose Decomposition → Wait for Confirmation → Create Subtask Issues → Comment on Parent
```

## Steps

### Step 1: Read the Parent Issue (MANDATORY)

```bash
gh issue view <issue-number>
```

Extract:
- Issue title and overall scope
- `Acceptance Criteria` (human section) and `Technical Acceptance Criteria` (AI section)
- `Files to Update/Create` (inside the parent Issue's collapsed
  `🤖 Implementation Spec (for AI agents)` block — `gh issue view` returns it in the
  raw body)
- Any existing dependencies or constraints

### Step 2: Analyze and Propose Decomposition

Identify subtask boundaries using these dimensions:

| Dimension | Example |
|-----------|---------|
| **Module boundary** | Changes touch independent modules (e.g., `adapters/` vs `domain/`) |
| **Concern boundary** | "add struct" vs "add tests" vs "update CLI flag" |
| **Sequential dependency** | Subtask B requires subtask A to merge first |
| **Risk boundary** | Mechanical rename vs logic change should be separate |

**Granularity rule**: Each subtask must be implementable in a single focused PR.

**Guard rails**:
- If the issue is already small enough for one PR → report "No split needed. This issue is already scoped for a single PR." Do NOT create any subtask Issues.
- If decomposition yields more than 7 subtasks → flag over-decomposition and suggest grouping before proceeding.
- **Line-count target**: Aim for ≤ 200 changed lines per subtask PR. If a subtask is estimated to exceed this, consider splitting it further. This is a guideline, not a hard limit.

Present the proposed subtasks to the user in this format:

```
Proposed split for #<parent>:

1. [Short title] — [one-line rationale]
2. [Short title] — [one-line rationale]
...

Dependencies:
- #2 depends on #1 (reason)

Proceed? (yes / adjust / cancel)
```

### Step 3: Wait for Explicit Confirmation

**Do NOT create any Issues until the user explicitly confirms.**

Accepted responses: "yes", "proceed", "go ahead", or equivalent affirmation.
If the user asks for adjustments, revise the proposal and present again.
If the user cancels, stop and report "Split cancelled."

### Step 4: Create Subtask Issues

**Once the user confirms in Step 3, execute all `gh issue create` commands immediately without additional prompts or pauses between issues. Do not ask for permission again.**

For each confirmed subtask, create a GitHub Issue using this template. It follows the
same human/AI split as `.claude/issue-guidelines.md`; the parent link is human-facing,
the inter-subtask dependency is AI-facing.

```markdown
## Summary
[1–2 sentences: what this subtask delivers.]

Part of #<parent-number>

## Why
- [Why this slice exists as its own PR — module/concern/risk boundary]

## Scope
**In**
- [What this subtask delivers]

**Out**
- [Explicitly left to sibling subtasks, by number when known]

## Acceptance Criteria
- [ ] [Behavior-level, human-verifiable outcome]

<details>
<summary>🤖 Implementation Spec (for AI agents)</summary>

## Context & Constraints
- Parent Issue: #<parent-number>
- Dependencies on other subtasks: [e.g. "Depends on #N merging first" or "None"]
- [Relevant invariants and existing patterns inherited from the parent Issue]

## Design Decisions
- [The slice boundary and why, in prose. Carry over the parent's decisions that
  constrain this subtask.]

## Files to Update/Create
1. `path/to/file.rs` — [what changes]

## Technical Acceptance Criteria
- [ ] All existing tests pass (`cargo test --all`)
- [ ] New tests added for new functionality (if applicable)
- [ ] Formatted with `cargo fmt --all`
- [ ] No new Clippy warnings (`cargo clippy --all-targets --all-features -- -D warnings`)

</details>
```

**Placement rules**: `Part of #<parent>` is a standalone line directly under `## Summary`
(no `## Parent Issue` heading — it is one line and does not need one). `Dependencies on
other subtasks` is a bullet in `## Context & Constraints`, never a top-level heading, so
that section names stay identical across all templates. Include `## Design Sketch` in the
human section only if the subtask introduces or changes types.

Use the `gh` CLI. The body contains HTML tags and backticks — pass it via a quoted
heredoc so the shell does not mangle `<details>` or fenced blocks:

```bash
gh issue create \
  --title "<subtask title>" \
  --label "<appropriate label>" \
  --assignee "<same assignee as parent, if any>" \
  --body "$(cat <<'EOF'
<subtask body>
EOF
)"
```

Record each created Issue number as you go.

### Step 5: Comment on Parent Issue

After all subtask Issues are created, post a comment on the parent Issue with a task list:

```bash
gh issue comment <parent-number> --body "$(cat <<'EOF'
## Subtasks

- [ ] #N1 — Title of subtask 1
- [ ] #N2 — Title of subtask 2
...

Created by /split. Dependencies noted in each subtask's description.
EOF
)"
```

The parent Issue is always left open as a tracking issue. Do not close it.

### Step 6: Report Completion

Output:
- Parent Issue number
- List of created subtask Issue numbers and URLs
- Confirmation that the parent Issue remains open as a tracking issue

## Subtask Issue Template Reference

See Step 4 above for the canonical subtask template. It is deliberately not duplicated
here — the previous duplicate is how this skill drifted from
`.claude/issue-guidelines.md`.

Section order at a glance:

Human: `## Summary` (+ `Part of #<parent>`) → `## Why` → `## Scope` → `## Acceptance Criteria`
AI (`<details>`): `## Context & Constraints` (parent link + dependencies) → `## Design Decisions` → `## Files to Update/Create` → `## Technical Acceptance Criteria`

## Example Usage

User: "split issue #120"

Claude executes /split skill:
1. Reads issue #120 (a large refactor touching 5 modules)
2. Proposes 4 subtasks with rationale and dependency order
3. Waits for user confirmation: "yes"
4. Creates Issues #121, #122, #123, #124 with proper templates
5. Posts task-list comment on #120
6. Reports: "Created 4 subtask Issues: #121, #122, #123, #124"
