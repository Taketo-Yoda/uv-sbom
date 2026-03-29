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

### Enforcement

When a user requests any operation listed above (even in Japanese), Claude MUST:

1. Recognize the operation type
2. Invoke the corresponding skill
3. Follow ALL steps defined in the skill, including pre-flight checks
4. Ensure all outputs (commits, PRs, Issues) are in English

## Feature Discussions

When the user proposes, discusses, or asks Claude to evaluate a new feature idea,
Claude MUST follow this process before responding with implementation suggestions.

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
invoke the `/ideate` skill (when available) or `/issue` skill directly.

| Operation | Skill | When |
|-----------|-------|------|
| Evaluate feature idea | (manual triage, see above) | Before any Issue |
| Draft Issue from approved idea | /ideate | Feature passed triage |
| Create Issue directly | /issue | Feature already approved by user |

## README Update Checklist

When updating README.md, check if the following files also need updates:

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
| `src/adapters/outbound/formatters/` | CycloneDX and Markdown output formatters |
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
| `GenerateSbomUseCase` | `src/application/use_cases/generate_sbom/` | Orchestrates SBOM generation |
| `Package` | `src/sbom_generation/domain/` | Core domain model for a dependency |

### Important Invariants

- **Config resolution order**: CLI args > environment variables > config file > defaults.
  This order is enforced in `config_resolver.rs` and must not be changed without updating tests.
- **Domain layer has no I/O**: `src/sbom_generation/` must never import from `adapters` or `ports`.
- **All GitHub artifacts (commits, PRs, Issues) must be in English** — enforced by skills in `.claude/skills/`.

### Files NOT to touch unless their issue explicitly targets them

- `src/adapters/outbound/network/` — HTTP client internals (unrelated to most refactors)
- `src/i18n/` — Locale catalogs (separate concern)
