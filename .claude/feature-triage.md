---
# Feature Triage for uv-sbom
#
# How to use this file:
# Read this BEFORE drafting any GitHub Issue for a new feature.
# Answer each question. If any STOP condition is met, do not create the Issue
# without first discussing with Taketo.
---

# Feature Triage Checklist

This checklist is for use by AI agents (Claude Code) when evaluating a proposed feature
for uv-sbom. Complete all checks before creating a GitHub Issue.

## Step 1: Scope Check (STOP conditions)

Answer each question. A "STOP" answer means the feature is likely out of scope.

| # | Question | STOP if... |
|---|----------|------------|
| 1 | Does the feature depend on uv.lock as its primary data source? | No → STOP: uv-sbom is uv-native by design |
| 2 | Does the feature produce or improve output that a developer reads directly? | No → STOP: we are not building a pipeline integration tool |
| 3 | Is the feature absent from the Anti-roadmap in product-vision.md? | No → STOP: feature is explicitly excluded |
| 4 | Does the feature avoid replicating functionality of OSV, Dependency-Track, or pip-audit? | No → STOP: integrate, do not duplicate |

If any STOP condition is met, write a comment explaining which condition was triggered
and what the user should do instead (e.g., use pip-audit for X).

## Step 2: Value Check (must pass at least one)

| # | Question | Pass condition |
|---|----------|----------------|
| A | Does this help the reader understand their dependency situation faster? | Yes |
| B | Does this reduce the number of steps the reader must take to act on the output? | Yes |
| C | Does this reduce noise (irrelevant data) in the output? | Yes |

If none of A/B/C pass, the feature is "Completeness for its own sake" — an anti-pattern
in uv-sbom's philosophy. Do not implement.

## Step 3: Differentiation Check (informational, affects priority)

| # | Question | Priority impact |
|---|----------|----------------|
| D | Would this require competitors (cyclonedx-python, pip-audit, Syft) to redesign their core data model to replicate? | Yes → High priority |
| E | Is this feature only possible because uv-sbom reads uv.lock (not installed environment)? | Yes → High priority |
| F | Does this strengthen the Upgrade Advisor or Resolution Guide capabilities? | Yes → High priority |

Features that pass D, E, or F should be prioritized in the Issue backlog.

## Step 4: Output Quality Check

Before finalizing the Issue, verify the proposed feature does NOT:
- [ ] Duplicate information already shown in another output section
- [ ] Display raw API data without normalization (e.g., raw PyPI license strings)
- [ ] Add fields that the reader cannot act on (e.g., build timestamps, package hashes)
- [ ] Reorder or restructure existing output without a clear readability improvement

## Triage Result Template

After completing the checklist, write the triage result in the Issue description:

```
## Feature Triage Result

- Step 1 (Scope): PASS / STOP (reason: ...)
- Step 2 (Value): PASS (criteria met: A / B / C) / FAIL
- Step 3 (Differentiation): D: yes/no, E: yes/no, F: yes/no
- Step 4 (Output Quality): PASS / FAIL (issue: ...)
- Priority recommendation: HIGH / MEDIUM / LOW / OUT OF SCOPE
```

## Examples

### Example: "Add support for poetry.lock"
- Step 1, Q1: STOP — feature does not use uv.lock as primary data source
- Result: Out of scope. Recommend: use a poetry-specific SBOM tool.

### Example: "Show which dependency introduced a vulnerable transitive package"
- Step 1: PASS (uses uv.lock graph data)
- Step 2: PASS (criterion B: reduces action steps — user doesn't need to trace manually)
- Step 3: E=yes (only possible from lock file graph), F=yes (strengthens Resolution Guide)
- Step 4: PASS
- Result: HIGH priority
