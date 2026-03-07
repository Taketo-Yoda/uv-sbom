# Output Design Standards: uv-sbom

This document defines concrete, actionable standards for evaluating and designing
uv-sbom output. It applies to both Markdown and JSON output formats.

**Before implementing any feature that affects output**, read this document and verify
your changes against the Anti-Patterns section.

---

## Core Output Principle

Every section of the output must answer one of these questions for the reader:

1. **What do I have?** (inventory: packages, versions, licenses)
2. **Is there a problem?** (vulnerabilities, license violations)
3. **What should I do?** (resolution guide, upgrade advisor)

Sections that answer the same question must be **merged**, not duplicated.

---

## Required Document Structure

Markdown output MUST follow this top-to-bottom order:

1. **Document title** — `# Software Bill of Materials (SBOM)`
2. **Summary block** — Key counts at a glance (packages, vulnerabilities, license violations)
3. **Direct Dependencies** — Packages explicitly declared in `pyproject.toml`
4. **Transitive Dependencies** — Grouped by which direct dependency introduces them
5. **Vulnerability Report** — Only when `--check-cve` is used
6. **Vulnerability Resolution Guide** — Only for transitive vulnerabilities
7. **License Compliance Report** — Only when `--check-license` is used

**REMOVED**: `## Component Inventory` section is deprecated. It was a full duplicate
of Direct + Transitive sections combined. Do **not** re-introduce it.

---

## Summary Block Specification

The summary block MUST appear immediately after the document title.
It provides a scannable overview before the reader commits to reading detail sections.

### Required format

```markdown
## Summary

| Item | Count |
|------|-------|
| Direct dependencies | 5 |
| Transitive dependencies | 23 |
| Vulnerabilities (actionable) | 2 |
| Vulnerabilities (informational) | 1 |
| License violations | 0 |
```

Show only rows that are relevant:
- Omit vulnerability rows if `--check-cve` was not used.
- Omit license violation row if `--check-license` was not used.

### Placement rule

The summary block is the **second section** of every Markdown SBOM document.
No content (except the document title) should appear before it.

---

## Heading and Emoji Formatting Rules

### Emoji in headings

- Always include a **space between emoji and text**: `### ⚠️ Warning` not `### ⚠️Warning`
- Use emoji only at the H3 level and below; H1 and H2 headings must **not** contain emoji
- Emoji are for visual scanning aid only; the text must be self-explanatory without them

### Severity emoji mapping (canonical)

| Severity | Emoji |
|----------|-------|
| CRITICAL  | 🔴 |
| HIGH      | 🟠 |
| MEDIUM    | 🟡 |
| LOW       | 🟢 |
| NONE/N/A  | ⚪ |

These must remain **consistent** across all output sections (vulnerability tables,
resolution guide, upgrade advisor). Do not introduce new emoji for severity levels.

### Heading level conventions

| Section Type | Level |
|-------------|-------|
| Document title | H1 (`#`) |
| Major sections (Summary, Direct Dependencies, etc.) | H2 (`##`) |
| Subsections (individual packages, severity groups) | H3 (`###`) |
| Details within a subsection | H4 (`####`) |

---

## Table Design Rules

### Column order for vulnerability tables

Always present columns in this order (omit columns not applicable):

`Package | Version | Fixed Version | CVSS | Severity | CVE ID`

**Rationale**: Readers scan left-to-right. "What package" and "what version I have"
must come before "how bad is it" (CVSS/Severity) and "where can I learn more" (CVE ID).

**Example**:

```markdown
| Package | Version | Fixed Version | CVSS | Severity | CVE ID |
|---------|---------|--------------|------|----------|--------|
| urllib3 | 1.26.5  | 2.0.7        | 7.5  | HIGH     | CVE-2023-45803 |
| requests | 2.28.0 | 2.32.0       | 6.1  | MEDIUM   | CVE-2023-32681 |
```

### Column order for dependency tables

| Package | Version | License |
|---------|---------|---------|

For transitive dependency tables, group rows by which direct dependency introduces them.

### License display

- Always normalize license strings before display
- Prefer SPDX identifiers (e.g., `MIT`, `Apache-2.0`, `GPL-3.0-only`) over raw PyPI strings
- When normalization is impossible, display the raw string with an `*` suffix and add a
  footnote explaining that the license could not be normalized
- Normalization is performed via `spdx_license_map.rs`

**Example of inconsistent raw strings that MUST be normalized**:

| Raw PyPI String | Normalized SPDX |
|----------------|----------------|
| `MIT` | `MIT` |
| `MIT License` | `MIT` |
| `MIT license` | `MIT` |
| `Apache Software License` | `Apache-2.0` |
| `BSD License` | `BSD-3-Clause` (if verifiable) |

---

## Anti-Patterns

The following patterns existed in earlier versions and must **NOT** be reintroduced.

### ❌ Duplicated inventory sections

**Problem**: Having both `## Component Inventory` (all packages) and separate
`## Direct Dependencies` / `## Transitive Dependencies` sections causes readers
to see the same package listed 2–3 times.

**Where this existed**: `render_components()` and `render_dependencies()` in
`markdown_formatter.rs` both output package lists.

**Rule**: Each package must appear **exactly once** in the inventory portion of the document.
Use `## Direct Dependencies` and `## Transitive Dependencies` as the only inventory sections.

---

### ❌ Missing top-level summary

**Problem**: Without a summary block, readers must scroll through the entire document
to understand the overall picture (e.g., "do I have any vulnerabilities?").

**Where this existed**: `render_header()` in `markdown_formatter.rs` — the header only
renders project metadata, not statistics.

**Rule**: Always render the summary block as the second section of the document,
immediately after the document title (`#` heading).

---

### ❌ Emoji adjacent to text without space

**Problem**: `### ⚠️Warning` renders poorly in some Markdown viewers and is hard to scan.

**Where this existed**: `render_actionable_vulnerabilities()` and
`render_informational_vulnerabilities()` in `markdown_formatter.rs`.

**Rule**: Always write `### ⚠️ Warning` with a space between the emoji and the text.
Apply this rule to ALL emoji in headings, not just warning icons.

---

### ❌ Raw inconsistent license strings

**Problem**: PyPI returns inconsistent license strings (`MIT`, `MIT License`, `MIT license`,
`Apache Software License`). Displaying these raw strings makes the license column noisy,
unprofessional, and hard to use for compliance review.

**Where this existed**: `render_components()` in `markdown_formatter.rs` — the license
field is rendered directly from the PyPI API response.

**Rule**: Normalize through `spdx_license_map.rs` before display. Fall back to the
raw string with an `*` suffix only if no mapping exists.

---

## Checklist for Output Feature Implementation

When implementing a feature that affects SBOM output (Markdown or JSON), verify:

- [ ] No section duplicates information already shown in another section
- [ ] Summary block is present and accurate (all counts reflect the actual output)
- [ ] Emoji in headings have a space between emoji and text
- [ ] Table columns follow the canonical order defined in this document
- [ ] New licenses are normalized through `spdx_license_map.rs` before display
- [ ] The change does not re-introduce any anti-pattern listed above
- [ ] H1 and H2 headings contain no emoji

---

Last Updated: 2026-03-07 (Issue #283)
