# Instructions for Claude Code

> **See CLAUDE.md → ## Skill Invocation Rules and ## Architecture Overview for authoritative guidance on skills and module structure.**

## Quick Reference

### High-Frequency Operations

| Operation | Required Approach |
|-----------|------------------|
| New branch | `git checkout -b <prefix>/<issue>-<desc> origin/develop` |
| Clippy check | `/pre-push` skill (NOT direct `cargo clippy`) |
| Format check | `/pre-push` skill or `cargo fmt --all -- --check` |
| Push code | `/pre-push` skill before `git push` |
| Create PR | `/pr` skill (`--base develop`) |
| Create Issue | `/issue` skill (English only) |
| Commit | `/commit` skill |

### Layer Rules

| Layer | Allowed | Prohibited |
|-------|---------|------------|
| `sbom_generation/` (Domain) | `std`, pure functions | I/O (`std::fs`, `reqwest`, etc.) |
| `application/` | Domain + Ports, `anyhow` | Direct I/O, adapters |
| `ports/` | Trait definitions | Implementations |
| `adapters/` | I/O libraries, port impls | Domain direct access |
| `shared/` | Common errors, security utils | Business logic |

### Key Invariants (Never Violate)

1. **Branch always from `origin/develop`** — never from `main`
2. **`cargo clippy` MUST include `-D warnings`** — CI enforces this (Issue #59)
3. **Never bypass skills** for commit/PR/push — skills encode CI-equivalent checks
4. **Domain layer has zero I/O** — no `std::fs`, no `reqwest`, no network
5. **All GitHub artifacts in English** — Issues, PRs, commits, comments

---

## Architecture

### Layer Responsibilities

1. **Domain Layer** (`sbom_generation/`) — Pure business logic; no I/O; all pure functions
2. **Application Layer** (`application/`) — Use case orchestration via ports; no direct I/O
3. **Ports Layer** (`ports/`) — Trait definitions only; no implementations
4. **Adapters Layer** (`adapters/`) — Concrete port implementations; executes I/O
5. **Shared Layer** (`shared/`) — Error types, type aliases, security validation functions

### Dependency Direction

```
Adapters → Application → Domain
    ↓           ↓
  Ports   ←   Ports
```

---

## Code Guidelines

### Error Handling

```rust
// ✅ Good: user-friendly, typed error
return Err(SbomError::LockfileParseError { path, details: e.to_string() }.into());
// ❌ Bad: opaque string
return Err(anyhow::anyhow!("Failed"));
```

Avoid `unwrap()` / `expect()` outside tests. Add context with `?`.

### Security (File Operations)

Always use `shared/security.rs` in adapters:

```rust
validate_regular_file(path, "uv.lock")?;
validate_file_size(file_size, path, MAX_FILE_SIZE)?;
```

Required checks: symlink validation, regular file validation, size limit.

Threats to mitigate: arbitrary file read (symlinks), DoS (huge files), TOCTOU, path traversal.

### Security (Network)

```rust
const MAX_RETRIES: u32 = 3;
const TIMEOUT_SECONDS: u64 = 10;
const RATE_LIMIT_MS: u64 = 100;  // 10 req/sec
```

### Type Aliases

Use type aliases for complex types to avoid Clippy warnings:

```rust
pub type PyPiMetadata = (Option<String>, Option<String>, Vec<String>, Option<String>);
```

### Naming Conventions

| Kind | Convention |
|------|-----------|
| Functions | `snake_case` |
| Types / Traits | `PascalCase` |
| Constants | `UPPER_SNAKE_CASE` |

### Adding Dependencies

| Layer | Allowed |
|-------|---------|
| Domain | `std` only |
| Application | `anyhow`, basic utilities |
| Adapters | I/O libraries |

Always use only required `features`. Update `.claude/project-context.md`.

---

## Testing Strategy

| Layer | Approach |
|-------|----------|
| Domain | Pure functions, no mocks needed |
| Application | Mock ports, test orchestration |
| Adapters | `tempfile` crate for real environment |

```rust
// Domain: pure function test
let result = DependencyAnalyzer::analyze(...);
assert_eq!(result, expected);

// Adapters: real environment with tempdir
let temp_dir = TempDir::new().unwrap();
let file_path = temp_dir.path().join("uv.lock");
```

---

## Git & Branch Rules

> **See CLAUDE.md → ## Skill Invocation Rules for the full skill routing table.**

### Branch Creation (CRITICAL)

Always branch from `origin/develop`:

```bash
git fetch origin
git checkout -b feature/<issue-number>-<description> origin/develop
```

### Branch Naming

| Priority | Label | Prefix | Example |
|----------|-------|--------|---------|
| 1 | `enhancement` | `feature/` | `feature/88-add-new-feature` |
| 2 | `bug` | `bugfix/` | `bugfix/42-fix-parsing` |
| 3 | `refactor` | `refactor/` | `refactor/30-cleanup` |
| 4 | `documentation` | `docs/` | `docs/50-update-readme` |
| 5 | (none) | `feature/` | `feature/99-misc` |

Hotfix (critical production fixes): `hotfix/<issue-number>-<description>`

### Pre-commit Hook

Runs `cargo fmt --all` automatically. Setup (once after cloning):

```bash
git config core.hooksPath .githooks
```

### Agent Skills

| Skill | Purpose |
|-------|---------|
| `/ideate` | Feature ideation (triage → analysis → Issue) |
| `/implement` | End-to-end implementation (branch → commit → PR) |
| `/commit` | Commit with branch guard + format/clippy checks |
| `/pr` | PR creation (pre-validation, base: `develop`) |
| `/pre-push` | Pre-push validation (clippy with `-D warnings`) |
| `/issue` | Issue creation (English, full template) |

**⚠️ CRITICAL (Issue #59)**: Never run `cargo clippy` directly — always use `/pre-push`. Without `-D warnings`, warnings pass locally but fail CI.

---

## Claude Code Workflow

### When Starting Work

1. ⚠️ **Check branch**: `git status` — if on `develop`/`main`, create feature branch from `origin/develop`
2. Read `.claude/project-context.md`

### During Coding

3. Identify the correct layer for changes (see Layer Rules above)
4. ⚠️ **Rust files changed?** → must run format check before push
5. Apply GoF patterns for duplicate code or complex conditionals (Strategy, Factory, Template Method)
6. Security review: file ops use `shared/security.rs`; network ops implement timeouts/retries
7. Add tests for new features
8. `cargo build` && `cargo test`
9. ⚠️ **Use `/pre-push` skill** — NOT manual `cargo clippy`

### When Completing Work

10. Update documentation as needed
11. Verify branch before committing
12. `/commit` skill → `/pr` skill (base: `develop`)

---

## Output Quality Review

When implementing features that affect SBOM output (Markdown or JSON), review against `.claude/output-design.md` before committing.

**Checklist**:
- [ ] No section duplicates information in another section
- [ ] Summary block present and accurate
- [ ] Emoji in headings have space between emoji and text
- [ ] Table columns follow canonical order in `output-design.md`
- [ ] New licenses normalized through `spdx_license_map.rs`
- [ ] No anti-patterns from `output-design.md` re-introduced

Read `.claude/product-vision.md` before implementing new output sections, CLI flags that change display, or changes to dependency grouping.

---

## PR Creation and Review Checklist

### Before Creating a PR

1. ⚠️ **Use `/pre-push` skill** — it runs all CI-equivalent checks including `-D warnings`
2. Verify base branch is `develop` (NOT `main`)
3. Review all changes: `git status && git diff`

Manual commands (if absolutely necessary — not recommended):

```bash
cargo fmt --all && cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings  # ⚠️ -D warnings MANDATORY
cargo test
git push
gh pr create --base develop --title "..." --body "..."
```

### When Responding to Review Comments

1. `gh pr view <PR-number> --comments` — read ALL comments
2. Create checklist of all requested changes
3. Address each item; re-run tests after changes
4. Cross-check after push — re-read all review comments

### Common Mistakes (Lessons from Incidents)

| # | Mistake | Fix | Incident |
|---|---------|-----|----------|
| 1 | Wrong base branch (`main` instead of `develop`) | Always `--base develop` | PR #31 |
| 2 | Forgot `cargo fmt --all` before push | Always run formatter | PR #31 |
| 3 | Missed review comment items | Read ALL comments, use checklist | PR #31 |
| 4 | `cargo clippy` without `-D warnings` | Use `/pre-push` skill | Issue #59 |
| 5 | Bypassed skills for common operations | Treat skills as the ONLY way | Issue #59 |
| 6 | Issue created in Japanese | Always verify English before submit | PR #121 |

---

## Important Constraints

### No Breaking Changes

- Do not delete or modify existing CLI options
- Maintain backward compatibility

### Code Quality Checklist (upon coding completion)

- [ ] GoF patterns applied where appropriate
- [ ] File ops use `shared/security.rs` (symlink, size, type checks)
- [ ] Network ops implement timeouts, retries, rate limiting
- [ ] No sensitive info in error messages (paths, internal structures)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
- [ ] `cargo test` passes
- [ ] Tests added for new features
- [ ] Public APIs have documentation comments (`///`)

---

## Frequently Asked Questions

**Q: Duplicate code or complex conditionals?**
Apply GoF patterns — Template Method (common algorithms), Strategy (behavior switching), Factory (object creation). Open a GitHub Issue before implementation.

**Q: How to add a new format?**
`SbomFormatter` trait → `adapters/outbound/formatters/` → `OutputFormat` enum → `FormatterFactory::create()` → `FormatterFactory::progress_message()` → tests.

**Q: Can I call external APIs in domain layer?**
No. Define a port, implement in an adapter.

**Q: File I/O in tests?**
Use `tempfile` crate.

**Q: Forgot security checks for file ops?**
Fix immediately. Use `shared/security.rs` validations. Add security violation test cases.

**Q: How to add a new license source?**
Implement `LicenseRepository` trait → new adapter in `adapters/outbound/` → wire DI in `main.rs` → add tests.

---

Last Updated: 2026-03-30

## Change History

| Date | Change | Reference |
|------|--------|-----------|
| 2026-03-30 | Restructured for AI context efficiency: added Quick Reference, extracted Issue Guidelines to `issue-guidelines.md`, condensed prose to tables | Issue #371 |
| 2026-01-17 | Added pre-commit hook for automatic formatting | Issue #102 |
| 2026-01-17 | Added "Never Bypass Skills" section, skill enforcement table, failure patterns | Issue #88 |
| 2026-01-17 | Added Mistake 4 & 5 to Common Mistakes (Clippy `-D warnings`, skill bypass) | Issue #88 |
| 2026-01-17 | Updated Pre-Push checklist to recommend `/pre-push` skill | Issue #88 |
| 2026-01-13 | Added Pre-Submission Verification to prevent non-English issues | Issue #69 |
| 2026-01-09 | Added GitHub Issue Creation Guidelines (now extracted to `issue-guidelines.md`) | Issue #33 |
| 2026-01-09 | Added PR Creation and Review Response Checklist | PR #31 |
| 2025-01-04 | Added Git/Branch Strategy section | — |
| 2025-01-04 | Added design pattern and security review to workflow | — |
