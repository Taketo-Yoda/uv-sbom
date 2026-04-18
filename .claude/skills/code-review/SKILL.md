---
name: code-review
description: Spawn a Reviewer Agent to evaluate code changes against architecture, design, and quality criteria
---

# /code-review - Code Review Skill

Spawns a dedicated Reviewer Agent to evaluate the current `git diff HEAD` against
architectural, design, and quality criteria specific to uv-sbom.

This skill does NOT re-run CI checks (cargo fmt, clippy). Those are enforced by the
`/commit` skill and the CI pipeline.

## Invocation

**Standalone**: Invoke at any time to review uncommitted changes.
**Integrated**: Called automatically by `/implement` Step 4.5 before `/commit`.

## Workflow

```
Step 1: Collect diff
Step 2: Spawn Reviewer Agent (foreground)
Step 3: Parse result (PASS / FAIL)
  └── PASS → report success, return control to caller
  └── FAIL → apply fixes, increment counter, return to Step 1
             (max 3 iterations; halt and report if still failing)
```

## Steps

### Step 1: Collect Diff and File Content

```bash
git diff HEAD --name-only   # list changed files
git diff HEAD               # full diff for the reviewer
```

For each file listed by `--name-only`, also read its **full current content**.
This is required for file-size checks and documentation coverage checks.

In addition, run the following scan and include its output as supplemental
context for criterion 11:

```bash
grep -rn 'eprintln!\|println!' src/ \
  | grep -v 'msgs\.\|Messages::' \
  | grep -v '#\[cfg(test)\]' \
  | grep -v '\.rs:.*//.*i18n-ok'
```

- Lines in **changed files**: flag as 🔴 MUST FIX under criterion 11.
- Lines in **unchanged files**: flag as 🟡 SHOULD FIX (pre-existing violation).

If `git diff HEAD` is empty, report "Nothing to review — no uncommitted changes."
and exit.

### Step 2: Spawn Reviewer Agent

Use the `Agent` tool with `subagent_type: "general-purpose"`, run **foreground**.

Pass the following prompt, substituting `<diff>` and `<file_contents>`:

---

```
You are a senior Rust engineer and software architect reviewing a code change for the
uv-sbom project. Evaluate ONLY the criteria listed below.
Do NOT check formatting or linting — those are handled by CI.

## Diff to Review
<diff>

## Full File Content (for each modified file)
<file_contents>

---

## Review Criteria

### 1. Hexagonal Architecture Compliance

Layer boundary violations (🔴 MUST FIX if any):
- Does src/sbom_generation/ import from src/adapters/ or src/ports/?
- Does new I/O logic (file, network, console) exist outside src/adapters/?
- Is a domain object (Package, Vulnerability, etc.) passed across a layer boundary
  without being converted to a DTO first?

Port/Adapter structure:
- Are new port traits placed under src/ports/outbound/ or src/ports/inbound/?
- Are new adapters placed under the correct src/adapters/outbound/ subdirectory?
- Does every new async trait method have #[async_trait] and Send + Sync bounds?

Config resolution:
- Is MergedConfig only constructed in src/cli/config_resolver.rs?
- Is the priority order (CLI > env vars > config file > defaults) maintained?

### 2. Separation of Concerns

Single Responsibility Principle:
- Does any single struct or impl block carry more than one distinct responsibility
  (e.g., data retrieval AND formatting)?
- Does the application layer (src/application/) perform domain logic rather than
  orchestration only?
- Does any adapter contain business rules (e.g., "should this vulnerability be reported?")?

Layer-appropriate logic:
- Is threshold/severity judgment delegated to ThresholdConfig in src/sbom_generation/services/?
  Do not reimplement match on Severity outside the domain services.
- Is license compliance checking done in LicenseComplianceChecker, not in formatters?
- Is read model construction (SbomReadModel) done in the application layer, not in adapters?

### 3. DRY Principle

General duplication:
- Is there duplicated logic (>3 identical lines) across multiple functions or files?
- Is license string normalization duplicated across adapters?

uv-sbom-specific DRY violations:
- Is i18n message formatting done via i18n::format() rather than inline format!()?
- Is severity comparison done via ThresholdConfig::is_above_threshold() rather than
  hand-written match blocks?
- Is file security validation done via src/shared/security.rs rather than inline fs calls?

### 4. Domain-Driven Design

Value object usage:
- Are raw String / f32 / u32 used where a value object exists
  (PackageName, Version, CvssScore, Severity)?
- Does a new domain concept lack a value object or enum that would prevent invalid states?
- Does a value object constructor (::new()) perform complete validation and return Result<T>?
  After construction, is the inner value accessed directly (e.g., .0) without re-validation?

Entity and aggregate integrity:
- Is Vulnerability always identified by its CVE ID (never by index or raw string comparison)?
- Is DependencyGraph or PackageVulnerabilities accessed directly on its inner collection,
  bypassing the aggregate root's methods?

Business logic placement:
- Is any business rule (vulnerability filtering, license policy evaluation, upgrade path
  computation) implemented in src/adapters/ or src/cli/ instead of
  src/sbom_generation/services/?

Error handling (🔴 MUST FIX if any):
- Is unwrap() or expect() used on a Result or Option that could fail at runtime?
- Is a SbomError variant available but ignored in favor of a generic anyhow::bail!?
- Is error context lost (e.g., .map_err(|_| ...))?

### 5. GoF Design Pattern Applicability

Flag only if applying the pattern would concretely simplify the code in the diff.
Do not flag patterns for hypothetical future use.

- **Strategy**: Is conditional logic switching between algorithms expressed as a
  match/if-else instead of a trait object or enum dispatch?
- **Factory / Builder**: Is a complex object constructed inline with many fields rather
  than via a dedicated builder?
- **Observer / Callback**: Is progress reporting coupled to a concrete type instead of
  the ProgressReporter port trait?
- **Decorator**: Is cross-cutting behavior (logging, retry, rate limiting) embedded
  inside a struct rather than wrapping it via a decorator adapter?
- **Template Method**: Is a multi-step algorithm duplicated with slight variations
  instead of sharing a common template with overridable steps?
- **Null Object**: Is an Option<VulnerabilityRepository> checked repeatedly with
  if let Some(...) instead of a no-op trait implementation?

### 6. Martin Fowler Refactoring Applicability

Flag only if the refactoring clearly applies to the changed code.

- **Extract Function**: Is a function longer than ~30 lines doing more than one thing?
- **Extract Class / Module**: Does a struct handle responsibilities for a separate type?
- **Replace Conditional with Polymorphism**: Is a match/if-else on a type replaceable
  by trait method dispatch?
- **Introduce Parameter Object**: Are 4+ related parameters always passed together?
- **Replace Magic Number with Symbolic Constant**: Are numeric/string literals
  hardcoded instead of named constants?
- **Decompose Conditional**: Is a complex boolean condition unreadable inline?
- **Move Function**: Is a function in the wrong module relative to the data it operates on?

### 7. File Size and Complexity

- **1000-line threshold — implementation logic (🟡 SHOULD FIX)**: If any modified file
  exceeds 1000 lines of non-test code, propose a concrete refactoring — identify which
  function/module to extract and the target location.

- **File bloated by tests (🔴 MUST FIX)**: If a file is large primarily because of a
  `#[cfg(test)]` block, flag as a MUST FIX violation: do NOT propose extracting to a
  sibling `tests.rs`. That is an anti-pattern that physically separates tests from the
  code they test. Recommended fix: split the implementation into sub-modules and add
  `#[cfg(test)] mod tests { use super::*; ... }` at the bottom of each sub-module.
  Retain only true integration-level tests in `mod.rs`.

- **Function length**: Flag any function exceeding 30 lines that mixes concerns.
- **Nesting depth**: Flag any block nested more than 4 levels deep.

Known large files (monitor for growth):
- src/adapters/outbound/formatters/markdown_formatter/mod.rs (~882 lines)
- src/application/read_models/sbom_read_model_builder/mod.rs (~845 lines)
- src/application/use_cases/generate_sbom/mod.rs (~652 lines)

### 8. Documentation Comments

- Every public struct, enum, trait, and function added or modified must have a
  `///` doc comment explaining its purpose. (🟡 SHOULD FIX if missing)
- Non-obvious logic must have an inline `//` comment.
- Port trait methods must document preconditions, postconditions, and error cases.
- Functions that can panic must have `/// # Panics`.
- Functions returning Result must have `/// # Errors`.

### 9. Testability

Dependency injection:
- Are concrete types hardcoded where a trait object or generic bound would allow
  test doubles? (🟡 SHOULD FIX)
- Is any new struct non-testable because it constructs its own dependencies internally
  instead of accepting them via constructor injection? (🟡 SHOULD FIX)

Test surface:
- Do new public functions or methods have corresponding unit tests?
- Are domain service methods tested in isolation without adapter dependencies?
- Are adapter implementations tested with TempDir (filesystem) or mock HTTP (network)?

Test code quality:
- Are test helper functions or fixtures duplicated across test modules?
- Do test names follow the pattern: test_<function>_<scenario>_<expected>?

Test placement:
- Are tests for a sub-module placed in the sub-module's own file with
  `#[cfg(test)] mod tests { ... }`? (🟡 SHOULD FIX if missing)
- Does a sibling `tests.rs` exist only to reduce line count in the parent module?
  Flag as anti-pattern — split the module instead. (🟡 SHOULD FIX)
- Exception: `tests/` at the crate root is correct for cross-module integration tests.

### 10. Security

File I/O safety (🔴 MUST FIX if violated):
- Is symlink_metadata() used (not metadata()) before opening files?
- Is is_symlink() checked and rejected before proceeding?
- Is file size validated before allocating memory?
- Is canonicalize() applied to prevent path traversal?
- Is there a TOCTOU gap (check-then-use without fd-level re-verification)?

External input validation:
- Are CLI arguments and config file values validated through typed constructors
  (PackageName::new(), Version::new()) rather than used as raw strings?

Network safety:
- Are new HTTP calls subject to timeout (30s), rate limiting (100ms interval),
  and batch size limits (max 100 per request)?
- Is response body size bounded before reading into memory?

Sensitive data:
- Are file paths, API responses, or config values included in error messages in a
  way that could expose sensitive environment details?

### 11. i18n Consistency

User-visible string bypass (🔴 MUST FIX if any):
- Does any new user-visible string bypass the i18n system (hardcoded English
  in `eprintln!`/`println!` output)?
- Is a new message key missing from either `EN_MESSAGES` or `JA_MESSAGES`
  in `src/i18n/mod.rs`?

Test coverage (🟡 SHOULD FIX):
- If `{}` placeholder order differs between EN and JA templates, is this
  covered by a dedicated unit test in `src/i18n/mod.rs`?

---

## Output Format (respond ONLY in this exact format)

### Result: PASS | FAIL

### Findings
[If PASS, write "No issues found."]
[If FAIL, list each finding as:]
- <severity> **[Criterion]** `path/to/file.rs:line`: Description of the violation and suggested fix.

Severity levels:
- 🔴 MUST FIX — blocks proceeding (architecture violation, security flaw, unwrap/panic)
- 🟡 SHOULD FIX — strong recommendation (DRY, DDD, file size, missing docs, testability)
- 🔵 CONSIDER — optional improvement (GoF pattern, Fowler refactoring)

**FAIL condition**: any 🔴 finding exists, OR 3 or more 🟡 findings exist.
**PASS condition**: only 🔵 findings (or no findings).

### Summary
[One-sentence overall assessment]
```

---

### Step 3: Parse Result

Extract `### Result: PASS | FAIL` from the Reviewer Agent's response.

**If PASS**: report findings (🔵 items if any) to the user, return control to caller.

**If FAIL** (iterations remaining):
- Display all findings grouped by severity: 🔴 first, then 🟡, then 🔵
- Apply fixes for every 🔴 and 🟡 finding
- Increment iteration counter
- Return to Step 1

**If FAIL after 3 iterations**:
- Report all remaining findings to the user
- Do **NOT** proceed to commit
- Ask: "Review failed after 3 iterations. Address the remaining issues manually, or cancel?"

## Severity Reference

| Severity | Condition | Action |
|----------|-----------|--------|
| 🔴 MUST FIX | Architecture violation, security flaw, `unwrap`/`panic` | Fix immediately; blocks commit |
| 🟡 SHOULD FIX | DRY, DDD, file size ≥1000 lines, missing docs, testability | Fix before commit |
| 🔵 CONSIDER | GoF pattern, Fowler refactoring | Advisory; does not block commit |

## Example Output

```
### Result: FAIL

### Findings
- 🔴 MUST FIX **Hexagonal Architecture** `src/sbom_generation/domain/package.rs:42`:
  Imports `reqwest` (HTTP client) directly in the domain layer.
  Suggested fix: Move HTTP logic to `src/adapters/outbound/network/`.

- 🟡 SHOULD FIX **DRY Principle** `src/adapters/outbound/formatters/cyclonedx.rs:88,112`:
  Identical license normalization logic duplicated in two functions.
  Suggested fix: Extract into `normalize_license()` in `src/shared/`.

- 🟡 SHOULD FIX **File Size** `src/adapters/outbound/formatters/markdown_formatter/mod.rs`:
  File is now 1,043 lines. Suggested refactoring: extract the vulnerability section
  renderer (~lines 620–780) into a new `vulnerability_section.rs` submodule.

- 🔵 CONSIDER **GoF: Strategy** `src/cli/config_resolver.rs:155-180`:
  The format selection logic (match on OutputFormat) could be expressed as a Strategy
  trait to simplify future format additions.

### Summary
One critical layer boundary violation and two strong-recommendation issues must be
resolved before this change can proceed to commit.
```
