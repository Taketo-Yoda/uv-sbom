# Test Placement Convention (canonical)

Single source of truth for where Rust tests live. Established by Issue #849 (the
rule was previously restated independently in `.claude/agents/qa.md` and twice in
`.claude/skills/code-review/SKILL.md`).

## Rule

- Unit tests live in a `#[cfg(test)] mod tests { use super::*; ... }` block **in the
  same file** as the code under test, at the bottom of the file.
- Do **not** create a sibling `tests.rs` (or `foo/tests.rs`) to hold a module's unit
  tests. Physically separating tests from the code they cover is an anti-pattern in
  this project, even when the goal is to reduce a file's line count.
- If a file is too large *because of its tests*, split the **module** into
  sub-modules by responsibility, each with its own `#[cfg(test)] mod tests` at the
  bottom — do not split the tests out.
- The crate-root `tests/` directory is reserved for integration tests that exercise
  the public API or the binary.

## Consumers

- `.claude/agents/qa.md` — applies this rule when suggesting where new tests go.
- `.claude/skills/code-review/SKILL.md` — owns the review *severity* for violations
  (this file only states the rule).
