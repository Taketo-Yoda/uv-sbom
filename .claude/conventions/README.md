# Convention Ownership (canonical)

Single source of truth for what a convention is, which file owns each one, and the
check every `.claude/` change runs against. Established by Issue #918, after #849's
"one owner, link to it" note did not stop #917's drafts from writing one rule into
three skills.

## What Is a Convention

A convention is any decision rule, table, condition, naming scheme, or command that
**two or more `.claude/` files act on**.

Test it mechanically: count the files whose behavior would change if the rule
changed. If the count is two or more, it is a convention, however it is framed. "A
step in three skills" is one rule with three consumers.

A rule that only one file acts on is that file's own procedure. Incident records and
change-history rows describe past events, so they do not count as consumers.

## Index

| Convention | Owner |
|------------|-------|
| Convention definition, ownership, and the check (this file) | `README.md` |
| Branch naming, branch base, PR base, Stacked Mode, who merges | `branching.md` |
| Local CI-check commands | `ci-checks.md` |
| Rust test placement | `testing.md` |
| What needs a CHANGELOG entry, per-feature entry ownership, reference numbers, non-owner PR line | `changelog.md` |

A new convention gets its own `.claude/conventions/<topic>.md` and a row in this
table, both in the same change.

Rules that `.claude/CLAUDE.md`'s charter blockquote assigns to `CLAUDE.md` stay owned
there, and the Ownership Rule below applies to them unchanged.

## Ownership Rule

- Each convention has exactly one owner, and the owner states it in full.
- Every other file states only its own action at that step, plus a link to the
  owner's heading (e.g. "branch per `.claude/conventions/branching.md` → "Branch
  Base""). It does not repeat the rule's conditions, table rows, or rationale.
- If a copy disagrees with its owner, the owner wins and the copy is replaced by a
  link.

## Exceptions

1. **Derived executable blocks**: a consumer that must execute an owner's command
   block may keep an inline copy, preceded by a `<!-- derived: <owner path> -->`
   marker. The owner defines which blocks may be derived and how a copy must match
   (see `ci-checks.md` → "Derived Copies").
2. **Labelled summaries**: a table that is explicitly labelled as a summary, names its
   owner, and states that the owner wins on conflict (e.g. `instructions.md` →
   "Layer Rules", `agents/architect.md` → "Design Pattern Reference").

## Convention Ownership Check

Run this check on any Issue draft, split proposal, implementation plan, or diff that
touches a file under `.claude/`:

1. Which rules does this change add or modify? State each one in a single sentence.
2. Which `.claude/` files act on each rule? Include files this change does not touch.
3. For each rule acted on by two or more files, which single file owns it? If no file
   owns it yet, name a new `.claude/conventions/<topic>.md` and its Index row, and add
   both to the change.
4. Does every other file carry only its own action plus a link, or a marked
   exception?

**Result**: write one line per rule, in the form
`<rule> → owner <path>; consumers <paths> (link only)`. If there is no such rule,
write `none — no rule acted on by two or more .claude/ files`.

A shared rule with no owner fails the check, and so does a consumer that restates
the rule. When the check fails, fix the change, not the result.

## Consumers

- `/issue` Step 3.5, and `.claude/issue-guidelines.md` → "Pre-Submission Verification"
- `/split` Step 2 (proposal) and Step 4 (carry-over)
- `/implement` Step 3.5, through `.claude/agents/architect.md`
- `/code-review` criterion 3 (which owns the severity)
