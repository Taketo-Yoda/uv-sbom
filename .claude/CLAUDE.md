# Project Instructions

## Issue-First Rule

**Before making any file change — code, configuration, skill, or documentation —
always create a GitHub Issue first by invoking the `/issue` skill.**

This rule applies to ALL file changes, including cases not listed in the Skill
Invocation Rules table below. No file should be created or modified without a
backing Issue.

### Exemptions (no Issue required)

- Fixing a typo or formatting error explicitly requested inline by the user
- Updating `## Architecture Overview` in this file after an implementation
  (covered by the `/implement` skill's Step 7)

### Why This Rule Exists

Without this rule, Claude may treat unlisted operations (e.g., creating a new skill
file, adding a config entry) as exempt from the issue-first workflow and proceed
directly to file changes. A backing Issue ensures every change is intentional,
reviewable, and traceable.

### Recent Incidents

- **2026-03-29**: Claude attempted to create `.claude/skills/split/SKILL.md` directly
  without creating a GitHub Issue first, because "creating a skill file" was not
  explicitly listed in the Skill Invocation Rules table. Fixed by Issue #382.

---

## Skill Invocation Rules

When the user requests any of the following operations, ALWAYS invoke the corresponding skill defined in `.claude/skills/` directory. Never execute these operations directly without following the skill procedures.

| User Request | Skill to Invoke | Key Requirements |
|--------------|-----------------|------------------|
| Commit changes | /commit | Run `cargo fmt`, `cargo clippy`, English message |
| Create PR | /pr | Run pre-flight checks, English title/body |
| Push to remote | /pre-push | Run all validations before push |
| Create Issue | /issue | English title/body, proper template |
| Implement Issue | /implement | Full workflow from branch to PR |
| Dependabot Alert | /dependabot | Use CVE/GHSA ID (never alert number), `security` label |
| Prepare Release | /release | Version bump, CHANGELOG update, PR to `develop` (then develop→main manually) |
| Sync CLI options to config | /sync-config | Audit `ConfigFile`, `MergedConfig`, `CONFIG_TEMPLATE` for gaps |
| Split Issue into subtasks | /split | Confirm decomposition before creating Issues; all Issues in English |
| Propose or evaluate a feature idea | /ideate | Run triage, competitive analysis, draft Issue |
| Review code quality before commit | /code-review | Spawn Reviewer Agent; do not recheck CI concerns (fmt/clippy) |

### Why This Rule Exists

Skills contain mandatory pre-flight checks and language requirements that prevent:
- CI failures from formatting issues (`cargo fmt --all -- --check`)
- Clippy warnings causing CI failures (`-D warnings` flag)
- Language inconsistencies in GitHub artifacts (all must be in English)
- Missing code quality validations
- Direct commits to protected branches (`main`, `develop`)

### Recent Incidents

- **PR #121**: Created in Japanese, `cargo fmt --all -- --check` failed in CI
- **Issue #59**: `cargo clippy` was run without `-D warnings`, causing CI failure after push
- **2026-04-18**: v2.2.0 release promoted an empty `[Unreleased]` section. Features added in PRs #441–#483 were never recorded in CHANGELOG. Fixed by Issue #491 (added gate in `/release` Step 3.6 and `/pr` Step 4.5).
- **2026-05-09 (Issue #511)**: `--check-abandoned` CLI flag was added without updating README.md, README-JP.md, `examples/sample-project/config/uv-sbom.config.yml`, or any example project README. Root cause: `/implement` Step 4 said "update docs as needed" without a concrete gate; `/pr` had no documentation backstop. Fixed by Issue #568 (`/implement` Step 4.3 CLI Flag Documentation Gate) and Issue #569 (`/pr` Step 4.6 CLI Flag Documentation Backstop).
- **2026-07-08 (Issue #669)**: The `--check-non-pypi` flag (Issue #627) satisfied `/implement` Step 4.3.D with a README paragraph and a hand-fabricated example-output block, but no shipped example project's `uv.lock` contains a non-PyPI source, so running the flag against any example produces empty output. Root cause: Step 4.3.D only required a README *mention*, not *proof* of non-empty output. Fixed by Issue #669 (Step 4.3.D now requires actually running the flag against example data and producing real, non-empty output; a missing trigger is a blocker, not a gap). Note: `/pr` Step 4.6.D has the same weakness and should be hardened in a follow-up Issue.

### Enforcement

When a user requests any operation listed above (even in Japanese), Claude MUST:

1. Recognize the operation type
2. Invoke the corresponding skill
3. Follow ALL steps defined in the skill, including pre-flight checks
4. Ensure all outputs (commits, PRs, Issues) are in English

## Feature Discussions

When the user proposes, discusses, or asks Claude to evaluate a new feature idea,
Claude MUST follow this process before responding with implementation suggestions.

### Step 0: Check current implementation state (MANDATORY — run before Step 1)

Before proposing or evaluating any feature, read these two files to build an exhaustive
list of already-implemented capabilities:

1. `src/cli/mod.rs` — all current CLI flags (e.g., `--severity-threshold`, `--license-allow`)
2. `src/config.rs` — all current config keys (e.g., `severity_threshold`, `license_policy`)

For each feature idea (your own or the user's), check whether it is already covered by an
existing CLI flag or config key. If it is, do NOT propose it as a new feature — instead,
state explicitly: "This is already implemented as `--flag-name` / config key `key_name`."

### Step 1: Read vision and triage files (MANDATORY)

Before responding to any feature proposal, read these two files:

1. `.claude/product-vision.md` — understand the product identity and design philosophy
2. `.claude/feature-triage.md` — apply the 4-step triage checklist

### Step 2: Run triage

Apply the checklist in `.claude/feature-triage.md` to the proposed feature.
Produce a triage result in the format defined in that file.

### Step 3: Respond with triage result

Structure your response as:

1. **Triage result** (from Step 2) — clearly state PASS/STOP/priority
2. **Recommendation** — one of:
   - "This fits the vision. Recommend creating an Issue." → invoke /ideate or /issue
   - "This is on the anti-roadmap. Here's why: [reason]."
   - "This is out of scope. A better tool for this is: [tool]."
   - "This needs more information: [specific question]."
3. **If PASS**: suggest next action (run /ideate skill to draft Issue, or /issue directly)

### When this process applies

Trigger this process when the user says anything like:
- "I want to add [feature]"
- "What if we supported [X]?"
- "Can uv-sbom do [Y]?"
- "Let's implement [Z]"
- "Feature idea: ..."

### Skill for feature ideation

If a feature passes triage and the user wants to proceed to Issue creation,
invoke the `/ideate` skill or `/issue` skill directly.

| Operation | Skill | When |
|-----------|-------|------|
| Evaluate feature idea | (manual triage, see above) | Before any Issue |
| Draft Issue from approved idea | /ideate | Feature passed triage |
| Create Issue directly | /issue | Feature already approved by user |

## Agent Invocation Rules

Role-based agents in `.claude/agents/` provide specialized perspectives for open-ended analysis tasks. Invoke the appropriate agent when you need domain expertise beyond what skills and context files provide.

| Situation | Agent to Invoke | File |
|-----------|----------------|------|
| Evaluating a feature proposal | PdM | `.claude/agents/pdm.md` |
| Reviewing code structure or module placement | Architect | `.claude/agents/architect.md` |
| Security review of new CVE/network code | Security Expert | `.claude/agents/security.md` |
| Reviewing English README or documentation | DevRel | `.claude/agents/devrel.md` |
| Reviewing `src/i18n/` or `README-JP.md` | i18n Specialist | `.claude/agents/i18n.md` |
| Reviewing test coverage for a new feature | QA Engineer | `.claude/agents/qa.md` |
| Checking release readiness before `/release` | Release Manager | `.claude/agents/release.md` |
| Planning decomposition of a large Issue before `/split` | PM | `.claude/agents/pm.md` |

### Agents vs Skills

- **Skills** = procedural workflows ("what steps to take") — e.g., `/commit`, `/release`
- **Agents** = domain perspectives ("what lens to apply") — e.g., PdM, Architect

Agents complement skills: the Release Manager agent judges readiness; the `/release` skill executes the mechanics.

---

## README Update Checklist

Trigger this checklist when **any** of the following is true:
- README.md content is being changed directly
- A new CLI flag or config key was added (see also: /implement Step 4.3)
- A new user-facing feature was implemented

When triggered, check if the following files also need updates:

| File | Action Required | Notes |
|------|-----------------|-------|
| README-JP.md | Translate changes | Full translation of README.md |
| python-wrapper/README.md | Reflect if applicable | PyPI-focused, keep concise |

### When to update each file

- **README-JP.md**: Always update when README.md content changes
- **python-wrapper/README.md**: Update when changes affect:
  - Installation instructions
  - Basic usage examples
  - New user-facing features (brief mention)
  - Version/badge updates

## Architecture Overview

### Design Pattern
Hexagonal Architecture (Ports & Adapters) with Domain-Driven Design principles.

### Module Structure

| Path | Responsibility |
|------|----------------|
| `src/cli/` | CLI entrypoint, argument parsing, config resolution |
| `src/cli/config_resolver.rs` | Merges CLI args / env vars / config file into `MergedConfig` |
| `src/application/` | Use cases, DTOs, factories, read models |
| `src/sbom_generation/` | Pure domain logic (no I/O dependencies) |
| `src/ports/` | Trait definitions for infrastructure (inbound/outbound) |
| `src/ports/inbound/` | Inbound port traits (e.g. use case interfaces) |
| `src/ports/outbound/` | Outbound port traits (e.g. repository, network interfaces) |
| `src/adapters/inbound/` | Inbound adapter implementations |
| `src/adapters/outbound/network/` | PyPI and OSV HTTP clients |
| `src/adapters/outbound/formatters/` | CycloneDX, Markdown, and Diff (Markdown/JSON) output formatters |
| `src/adapters/outbound/filesystem/` | File read/write adapters |
| `src/adapters/outbound/uv/` | uv.lock file parsing |
| `src/adapters/outbound/console/` | Console/progress reporter adapter |
| `src/shared/` | Common error types and utilities |
| `src/config.rs` | `ConfigFile` struct (deserialized from TOML config) |
| `src/i18n/` | Locale and message catalog |

### Key Types

| Type | Location | Role |
|------|----------|------|
| `MergedConfig` | `src/cli/config_resolver.rs` | Final resolved config (CLI > env > file > default) |
| `ConfigFile` | `src/config.rs` | Raw deserialized config file struct |
| `SbomRequest` / `SbomResponse` | `src/application/dto/` | Input/output for the main use case |
| `GenerateSbomUseCase<LR,PCR,LREPO,PR,VREPO,MREPO,PCREPO=()>` | `src/application/use_cases/generate_sbom/` | Orchestrates SBOM generation; 6th param `MREPO: MaintenanceRepository` added in #555; 7th param `PCREPO: PythonCompatibilityRepository` (defaults to `()`) added in #681 |
| `CheckAbandonedPackagesUseCase` | `src/application/use_cases/check_abandoned_packages.rs` | Fetches PyPI maintenance info for all packages with progress bar and soft-fail per package |
| `DiffRequest` | `src/application/dto/diff_request.rs` | Input DTO for the diff use case (source, project_path, check_cve) |
| `DiffResult` | `src/application/dto/diff_result.rs` | Output of `GenerateDiffUseCase::execute`; wraps domain `DependencyDiff` with `Option<CveDeltaView>` to keep domain layer free of read-model dependencies |
| `GenerateDiffUseCase<LR,DLR,VR>` | `src/application/use_cases/generate_diff.rs` | Orchestrates dependency diff: reads current via LockfileReader, base via DiffLockfileReader, runs DependencyDiffAnalyzer, optionally fetches CVE delta via VulnerabilityRepository; 3rd param `VR` (default `()`) added in #599 |
| `CveDeltaView` / `CveDeltaEntry` | `src/application/read_models/cve_delta_view.rs` | Read model for CVE exposure diff between two lock file snapshots; wired into `GenerateDiffUseCase` in #599; consumed by diff formatters (Markdown/JSON) in #600 |
| `Package` | `src/sbom_generation/domain/` | Core domain model for a dependency |
| `GroupReachabilityAnalyzer` | `src/sbom_generation/domain/services/group_reachability_analyzer.rs` | Pure domain service for BFS-based group reachability traversal; wired into `GenerateSbomUseCase` via `apply_group_filter` in #623 |
| `GroupRoots` | `src/ports/outbound/lockfile_reader.rs` | Type alias `HashMap<String, Vec<String>>` mapping dependency group name → root package names; extracted from `[manifest.dependency-groups]` in `uv.lock`; consumed by group reachability traversal in #622; wired into use case in #623 |
| `NonPyPiPackageView` / `NonPyPiPackagesReport` | `src/application/read_models/non_pypi_package.rs` | Read model for packages sourced from non-PyPI origins (git, url, private registry); populated by `GenerateSbomUseCase` when `check_non_pypi` is true; rendered by the Markdown formatter's `non_pypi_packages` section (#656, #660) |
| `PythonIncompatibilityView` / `PythonCompatibilityReport` | `src/application/read_models/python_compatibility.rs` | Read model for packages incompatible with a target Python version, independent of how `requires_python` data is fetched; added in #679; constructed by `CheckPythonCompatibilityUseCase` in #680; wired into `GenerateSbomUseCase`/`main.rs` via `--target-python` in #681; `SbomReadModel.python_compatibility` not yet rendered by any formatter (see #689) |
| `CheckPythonCompatibilityUseCase` | `src/application/use_cases/check_python_compatibility.rs` | Fetches `requires_python` for all packages concurrently via `PythonCompatibilityRepository` (bounded by `MAX_CONCURRENT`), evaluates with `is_incompatible`, and builds a `PythonCompatibilityReport`; soft-fails per-package fetch errors; added in #680; wired into `GenerateSbomUseCase` in #681 |
| `ProgressBarHandle` | `src/application/use_cases/progress_bar.rs` | Shared indicatif progress-bar helper (background-thread polling an `AtomicUsize` counter) used by `CheckAbandonedPackagesUseCase` and `CheckPythonCompatibilityUseCase` to avoid duplicating the spawn/poll/finish pattern |

### Important Invariants

- **Config resolution order**: CLI args > environment variables > config file > defaults.
  This order is enforced in `config_resolver.rs` and must not be changed without updating tests.
- **Domain layer has no I/O**: `src/sbom_generation/` must never import from `adapters` or `ports`.
- **All GitHub artifacts (commits, PRs, Issues) must be in English** — enforced by skills in `.claude/skills/`.

### Files NOT to touch unless their issue explicitly targets them

- `src/adapters/outbound/network/` — HTTP client internals (unrelated to most refactors)
- `src/i18n/` — Locale catalogs (separate concern)

## Dead Code Policy

### Prohibition: Speculative `#[allow(dead_code)]`

Never add `#[allow(dead_code)]` to silence the dead_code lint speculatively.
Examples of prohibited patterns:

```rust
// ❌ PROHIBITED — "Reserved for future issue" pattern
#[allow(dead_code)]  // Reserved for Issue #N
pub fn compute_something(&self) -> Result<Output> { ... }

// ❌ PROHIBITED — stub field without current consumer
#[allow(dead_code)]  // Will be used in Issue #M
pub current_version: String,
```

**Why**: These stubs accumulate silently, become technical debt, and require
large-scale cleanup (e.g., PR #488: 388 lines deleted across 26 files).
Bulk removal is error-prone when multiple structs share field names.

### Acceptable Use Cases

`#[allow(dead_code)]` is allowed ONLY for:

| Use Case | Required Format |
|----------|-----------------|
| serde wire-format fields that are deserialized but not yet processed in Rust | `#[allow(dead_code)] pub experimental_flag: Option<bool>` on a `#[derive(Deserialize)]` struct |
| `#[cfg(test)]`-bounded test helpers defined in a test module | Inside `#[cfg(test)] mod tests { ... }` only |
| Foundational type/function in a sequential PR split whose consumer is a concrete tracked issue, not yet reachable from the binary | Must use the standardized format: `#[allow(dead_code)] // WIRE(#N): remove when <description>`. The attribute MUST be removed in Issue #N via the Step 4.0 cleanup gate. |

In all cases, add a comment explaining WHY the field is intentionally unused in
production code. For the WIRE case, the consuming issue number (#N) MUST exist as
an open GitHub Issue, and the description after the colon MUST state the removal
condition clearly.

### YAGNI Workflow

If you identify that a future issue will need a field/method that doesn't exist yet:

1. **Do NOT add the stub field.** The future issue will introduce it when needed.
2. **Note the need** in the current Issue or PR description.
3. **Open a new Issue** describing what needs to be added and why.
4. Close the current PR without the stub. The future issue owns its own implementation.

### Clippy Requirement

CI and all local checks MUST use `--all-targets --all-features`:

```bash
# ✅ CORRECT — catches dead code in binary and integration-test targets
cargo clippy --all-targets --all-features -- -D warnings

# ❌ WRONG — misses dead code visible only from binary/integration targets
cargo clippy --lib -- -D warnings
```

This is already enforced in `.claude/skills/commit/SKILL.md` and
`.claude/skills/pr/SKILL.md`. Do not weaken this to `--lib` only.

### Recent Incidents

- **2026-05-24 (Issue #598)**: Added `CveDeltaView` and `CveDeltaEntry` read model
  types with `#[allow(dead_code)]` in a standalone foundational PR. Free-form comment
  was not machine-scannable, so removal in #599 was not enforced. Fixed by Issue #604
  with the WIRE convention and the Step 4.0 cleanup gate.
