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

Last Updated: 2026-03-07 (Issue #283)
