# Subtask Links (canonical)

Single source of truth for how a subtask Issue names its parent epic and the sibling
subtasks it depends on. Established by Issue #1040, which moved `/split` onto native
GitHub sub-issues while older epics still carry only the text form.

## Parent Link

A subtask names its parent in three places, and `/split` writes all of them:

| Form | Where | Purpose |
|------|-------|---------|
| `Part of #<parent>` | A standalone line directly under `## Summary` in the subtask body (no heading of its own) | Human-readable in the raw body; the only form on epics split before #1040 |
| `- Parent Issue: #<parent>` | The first bullet of `## Context & Constraints`, inside the collapsed AI section | Keeps the AI section self-contained for implementers that read only that block |
| Native sub-issue parent | `gh issue create --parent <parent>` (or `gh issue edit <N> --parent <parent>` afterwards) | Progress count on the parent, parent breadcrumb on the child, queryable as `gh issue view <N> --json parent` |

## Reading the Parent

A reader that needs a subtask's parent accepts **either** the `Part of #N` line in the
body or the native `parent` field. Never require the native field alone —
subtasks created before #1040 have only the line.

## Dependency Link

A subtask that must wait for a sibling records the dependency in two ways:

- Native blocked-by: `gh issue create --blocked-by <N1>,<N2>` (comma-separated real
  Issue numbers) or `gh issue edit <N> --add-blocked-by <M>`. It records *that* the
  dependency exists.
- The `Dependencies on other subtasks` bullet in `## Context & Constraints`. It explains
  *why* the dependency exists.

## Consumers

- `/split` Step 4 (writes the links) and Step 6 (reports links that could not be made)
- `/release` Step 3.6 Merged-PR Audit (reads the parent per "Reading the Parent")
