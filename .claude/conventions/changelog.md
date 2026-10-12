# CHANGELOG Ownership Convention (canonical)

Single source of truth for which changes need a `CHANGELOG.md` entry, which Issue
writes it, and how entries reference their Issues. Established by Issue #917, after
`--check-exploitability` (#812) shipped across eight PRs with no entry, because no step
owned the entry for a split feature.

## What Needs an Entry

A change needs an `[Unreleased]` entry when an end user can observe it in how the tool
behaves:

- a new, changed, or removed CLI flag, config key, or output
- a behavior change, including a deprecation or an observable performance improvement
- a bug fix
- a security fix, including a dependency update made for security

These changes need no entry, because the tool behaves the same afterwards:

- internal refactors, tests, CI changes, and non-security dependency bumps
- documentation-only changes (README, examples, doc comments)
- changes confined to `.claude/` (skills, agents, conventions) or to other
  contributor-only process files

## Reference Numbers

Every entry ends with a parenthesised list of `#N` references, e.g. `(#888)` or
`(#812, #875, #876)`.

- Cite Issue numbers. Use a PR number only when there is no Issue.
- A feature split into subtasks also cites its parent epic's number.

The `/release` merged-PR audit matches merged PRs to entries through these numbers
alone, so an entry without them is invisible to the audit.

## Ownership Per Feature

One user-facing feature gets one entry, however many PRs build it.

- **Owner**: exactly one subtask of a split epic writes the entry. By default, the
  owner is the subtask that makes the feature reachable from the binary. For #812,
  that was the wiring subtask #878.
- **Extenders**: a later subtask that changes user-visible behavior of the same
  feature extends the owner's entry instead of adding a new one. An example is a docs
  subtask that adds attribution.
- The owner and every extender list `CHANGELOG.md` in their Issue's
  `## Files to Update/Create`. No other subtask lists it.
- The entry's reference list includes the parent epic's number, so the audit can
  match every subtask's PR through it.

## Who Writes the Entry

| Issue | Action |
|-------|--------|
| Standalone (not a subtask) and needs an entry per "What Needs an Entry" | Writes its own entry |
| Standalone and needs no entry per "What Needs an Entry" | Writes nothing |
| Subtask whose Issue lists `CHANGELOG.md` (owner or extender) | Writes or extends the feature's entry |
| Any other subtask of an epic | Writes nothing; its PR body carries the "Non-Owner PR Line" |

## Non-Owner PR Line

A non-owning subtask's PR body contains this line under `## Related Issue`:

    CHANGELOG: owned by #<owner-subtask> (Part of #<parent>)

A PR that carries this line passes the CHANGELOG gate without an entry. A PR without
it is treated as an ordinary PR.

## Consumers

- `/split` Step 2 (`CHANGELOG owner` block) and Step 4 (carry-over)
- `/implement` Step 4.4
- `/pr` Step 4.5 (skip list and decision table)
- `/release` Step 3.6 Merged-PR Audit, which matches on "Reference Numbers"
- `.claude/agents/release.md` (completeness check)
