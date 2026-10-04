# CI Check Commands (canonical)

Single source of truth for the local quality-check commands. Established by Issue
#849 after copies under `.claude/` drifted to weakened forms
(`cargo clippy -- -D warnings`, bare `cargo test`).

## Canonical Command Block

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

This block mirrors exactly what runs automatically:

| Where | What it runs |
|-------|--------------|
| `.githooks/pre-push` | All three commands above, on every `git push` |
| `.githooks/pre-commit` | `cargo fmt --all` (write mode), re-staging formatted files |
| `.github/workflows/ci.yml` | All three commands above, plus CI-only `cargo test --all --release` and `cargo build --release` |

Run `make setup` once after cloning to activate the hooks.

To **fix** formatting (rather than check it), run `cargo fmt --all` — the write-mode
form. Skills that intentionally format before checking (e.g. `/release`) use it; this
is the only sanctioned deviation from the block above.

## Clippy: `--all-targets --all-features` is mandatory

```bash
# ✅ CORRECT — catches dead code in binary and integration-test targets
cargo clippy --all-targets --all-features -- -D warnings

# ❌ WRONG — misses dead code visible only from binary/integration targets
cargo clippy --lib -- -D warnings

# ❌ WRONG — same gap, plus test targets are not linted
cargo clippy -- -D warnings
```

`-D warnings` is required because CI fails on any warning (Issue #59: clippy run
without it passed locally and failed after push). Do not weaken the flags to `--lib`
or drop `--all-targets --all-features`.

## Derived Copies

A skill that must *execute* these commands as a step (e.g. `/pr` pre-flight,
`/release`, `/sync-config`) may keep an inline copy so it does not need an extra
file read at runtime. Such a copy MUST:

- be byte-identical to the canonical block's command lines (or `cargo fmt --all` per
  the write-mode note above), and
- be preceded by the marker `<!-- derived: .claude/conventions/ci-checks.md -->`.

Files that only *cite* the rule (FAQ, policy, checklists) link to this file instead
of restating it.
