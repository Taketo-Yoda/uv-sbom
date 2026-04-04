# Product Vision: uv-sbom

This document provides the "why" behind every design decision in uv-sbom.
It is intended to be read by AI agents and developers before implementing any feature
that affects output format, structure, or user experience.

---

## Project Identity

uv-sbom's core differentiator is **human readability**.

Unlike general-purpose SBOM tools (Syft, cyclonedx-python, pip-audit) that prioritize
machine-readable formats and comprehensive coverage, uv-sbom is designed to produce output
that a developer or security engineer can read, understand, and act on immediately — without
needing a separate viewer or parser.

The name reflects this focus: it is built specifically for **uv-managed Python projects**,
with deep understanding of the `uv.lock` format and uv's dependency resolution model.

---

## Target Users

### 1. Python Developers using uv

**Goal**: Quickly understand what packages their project depends on, and whether any
license or vulnerability issues exist.

**What they need**:
- A clear, readable summary of direct and transitive dependencies
- License information in a normalized, consistent format
- A way to quickly check if anything needs attention before shipping

**What they do NOT need**:
- Machine-readable SBOM formats (they use human-readable Markdown)
- Exhaustive lists of every installed package (they care about what they explicitly chose)

### 2. Security Engineers reviewing Python projects

**Goal**: Identify vulnerabilities in a project's dependency tree and determine what
action to take.

**What they need**:
- A prioritized list of vulnerabilities (not just a dump)
- Actionable guidance: which package to upgrade, to what version
- Clear distinction between direct and transitive vulnerabilities

**What they do NOT need**:
- Raw CVE data without context
- Identical information repeated across multiple sections

### 3. Compliance Reviewers checking license compatibility

**Goal**: Verify that all dependencies use licenses compatible with the project's
license policy.

**What they need**:
- Normalized SPDX license identifiers (not raw PyPI strings)
- A clear list of which packages have which licenses
- Immediate identification of potentially incompatible licenses

---

## Competitive Positioning

| Aspect | uv-sbom | cyclonedx-python | pip-audit | Syft |
|--------|---------|-----------------|-----------|------|
| Primary format | Human-readable Markdown | CycloneDX JSON | Terminal text | Multiple formats |
| Data source | `uv.lock` (locked deps) | `.venv` (all installed) | pip/requirements | Installed env |
| Actionability | Resolution Guide + Upgrade Advisor | None | None | None |
| uv support | Native | Not supported (as of v7.2.1) | Indirect | Limited |
| Target audience | Developers & security engineers | Security toolchains | Quick CLI scans | Enterprise SBOM pipelines |

> **Note**: The table above reflects the founding competitive analysis (snapshot from 2026-03-07).
> For current tool versions and feature status, see `.claude/competitive-landscape.md`.

### What we intentionally do differently

**vs. cyclonedx-python**: We produce Markdown first, machine-readable JSON second.
A developer running `uv-sbom` should be able to read the output without a viewer.

**vs. pip-audit**: We read from `uv.lock`, not the installed environment. This means
we report what the project *declares*, not what happens to be installed. We also
provide upgrade paths, not just vulnerability lists.

**vs. Syft**: We are purpose-built for uv. We understand uv's lock file format and
can accurately distinguish direct from transitive dependencies. Syft treats all
installed packages as equal.

---

## Structural Barriers

These are not just features we have that others lack — they are architectural constraints
that prevent competitors from replicating our advantages incrementally.

### Why competitors cannot easily replicate uv-native support

**cyclonedx-python** and **pip-audit** operate on the *installed environment* (`.venv`),
not on the lock file. Switching to lock-file-based analysis would require a fundamental
redesign of their data model — it is not an incremental improvement. Their entire analysis
pipeline assumes "what is installed" as the source of truth.

**Syft** is a general-purpose tool designed to handle any package ecosystem (containers,
language runtimes, OS packages). Adding deep `uv.lock` understanding would require
maintaining uv-specific parsing logic that conflicts with their universality goal and
increases maintenance surface area.

uv-sbom's lock-file-first approach is foundational, not a feature. This means:
- Accurate direct/transitive distinction (only possible from lock file metadata, not `.venv`)
- Reports what the project *declares*, not what happens to be installed
- Immune to environment contamination (extra packages installed manually, virtual env state)
- Consistent output regardless of whether `uv sync` has been run

### Why human-readable output is structurally different

Competitors produce human-readable output as a secondary goal (a `--format text` flag or
an export/view command added later). uv-sbom's Markdown formatter is the *primary output
path*: every design decision — section order, column selection, summary block placement —
optimizes for readability first.

Adding a Markdown export to cyclonedx-python would produce a mechanical rendering of
CycloneDX fields. It would not produce the opinionated, reader-first output that uv-sbom
generates, because the underlying data model was not designed with that goal.

### Why Upgrade Advisor is structurally differentiated

Providing actionable upgrade paths requires combining three independent data sources:

1. Knowledge of which version fixes a CVE (OSV API `affected[].ranges[].fixed`)
2. The current version in the lock file (uv.lock)
3. The dependency graph to identify which *direct* dependency is the root cause of a
   transitive vulnerability

pip-audit and cyclonedx-python do not combine these three. pip-audit reports CVEs but
not fixed versions derived from OSV ranges. Neither tool distinguishes root-cause
transitive issues from direct issues in their output.

uv-sbom's Resolution Guide was designed from the ground up to surface root-cause
transitive issues with their upgrade path — a capability that requires all three
data sources to be integrated at design time.

---

## Feature Prioritization Principle

When evaluating a proposed feature, ask:

1. **Does it help the reader understand their dependency situation faster?**
   - Example: A summary block at the top answers this — readers get the overall picture immediately.

2. **Does it reduce the steps needed to act on the information?**
   - Example: The Upgrade Advisor shows `requests 2.28.0 → 2.32.0` — readers don't need
     to look up the fixed version themselves.

3. **Does it reduce noise (irrelevant data for the reader's use case)?**
   - Example: Showing only transitive vulnerabilities in the Resolution Guide (not direct ones,
     which the user can upgrade directly) reduces noise.

If the answer to all three is "no", reconsider whether the feature belongs in uv-sbom.

### Anti-features to avoid

- **Completeness for its own sake**: Adding every possible SBOM field when readers don't
  need it (e.g., package hashes, build timestamps in Markdown output).
- **Duplication**: Showing the same package in three different sections (Component Inventory,
  Direct Dependencies, Transitive Dependencies) to appear more comprehensive.
- **Raw data dumps**: Exposing internal data structures or unprocessed API responses
  (e.g., raw PyPI license strings) instead of normalized, reader-friendly output.

---

## Anti-roadmap: What uv-sbom Will Not Do

These are not gaps — they are deliberate boundaries that preserve the product's focus.
When a feature request matches one of these entries, it should be declined with a reference
to this table rather than debated from scratch.

| Feature | Why We Will Not Add It |
|---------|------------------------|
| Support for `pip` requirements.txt | We are uv-native by design. Supporting pip would dilute the lock-file-first model and duplicate pip-audit's purpose. Users of pip should use pip-audit. |
| Support for `poetry.lock` / Pipenv | Same principle: each ecosystem deserves a purpose-built tool. Adding poetry support would make uv-sbom a general-purpose tool, which conflicts with our identity. |
| GUI or web interface | Our target users are developers and security engineers working in terminals and CI pipelines. A GUI adds complexity without serving the core use case. |
| SBOM ingestion / merging | We are a generator, not a pipeline orchestrator. Ingesting, merging, or comparing SBOMs belongs in dedicated tools like Dependency-Track or SBOM management platforms. |
| Custom vulnerability databases | OSV is the authoritative, community-maintained source. Supporting custom databases would require schema translation, maintenance burden, and creates a support surface we cannot own. |
| Package hash verification | Hashes are a deployment-time integrity concern, not a developer-facing SBOM concern. Including them in Markdown output adds noise without actionability for our target users. |
| SBOM diff / comparison | Valuable, but belongs in a separate tool. Adding diffing here would expand scope beyond "understand your current state" and introduce a second mental model into the tool. |
| Real-time monitoring / alerts | uv-sbom is a point-in-time analysis tool designed for human-triggered or CI-triggered runs. Continuous monitoring belongs in CI pipelines or dedicated monitoring services. |
| Support for non-Python ecosystems | We understand Python and uv deeply. Expanding to Node.js, Rust crates, or Go modules would dilute that depth and replicate what Syft already does generically. |

**Guiding principle**: If a feature is better served by an existing tool in the ecosystem,
document how to integrate with that tool rather than replicate it inside uv-sbom.

---

## Design Philosophy: "Actionable over Exhaustive"

uv-sbom prioritizes actionability over exhaustiveness. This means:

- If a reader sees a vulnerability, they should also see what to do about it.
- If a reader sees a license, it should be in a format they recognize (SPDX), not
  whatever string PyPI happened to return.
- If a reader sees a dependency list, it should be organized by relationship
  (direct vs. transitive), not alphabetically dumped.

When in doubt, ask: **"What does the reader do next?"** The output should make that
next step obvious.

---

## Feature Decision Flow for AI Agents

When evaluating a proposed feature, answer these questions in order. Stop at the first
"No" and do not proceed to implementation without discussing with the project owner.

1. **Is it uv.lock-specific?**
   - Yes → Continue to question 2.
   - No → Likely out of scope. Ask: does a better-suited tool already handle this?
     If yes, recommend that tool instead. If no, escalate to project owner.

2. **Does it make output more actionable for the reader?**
   Specifically: does it help the reader understand their dependency situation faster,
   reduce the number of steps needed to act on the information, or reduce noise?
   - Yes to at least one → Continue to question 3.
   - No to all three → Do not implement. This is "completeness for its own sake."
     Document the reasoning in the Issue comment.

3. **Is it listed in the Anti-roadmap?**
   - No → Continue to question 4.
   - Yes → Do not implement. Reference the Anti-roadmap entry in the Issue comment
     and close the Issue as "wontfix."

4. **Would a competitor be forced to redesign their core data model to replicate it?**
   - Yes → High priority. This reinforces our structural barriers.
   - No → Lower priority. Implement only if questions 1–2 are clearly satisfied.

5. **Does it add noise or duplication to the output?**
   - No → Approved for implementation planning.
   - Yes → Reject. Reference the "Actionable over Exhaustive" principle in the Issue.

### Decision Flow Summary Table

| Question | Yes | No |
|----------|-----|----|
| 1. uv.lock-specific? | Continue | Likely out of scope |
| 2. Makes output actionable? | Continue | "Completeness for its own sake" — reject |
| 3. On the Anti-roadmap? | Reject as wontfix | Continue |
| 4. Forces competitor data model redesign? | High priority | Lower priority |
| 5. Adds noise or duplication? | Reject | Approved |

---

Last Updated: 2026-03-28 (Issue #367)
