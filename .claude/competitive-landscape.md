# Competitive Landscape

Last full review: 2026-03-28
Review cadence: Update whenever a new version of a competing tool is released,
or when uv-sbom adds a feature that may change the competitive picture.

## How to use this file

This file is read during feature triage (Step 3 of /ideate skill) to determine
whether a proposed feature is differentiated from existing tools.

Before relying on any entry, check whether it is stale (last-verified date > 3 months ago).
If stale, run the verification command to update.

---

## cyclonedx-python

| Attribute | Value | Last Verified |
|-----------|-------|--------------|
| Latest version | 7.2.1 | 2026-03-28 |
| uv.lock support | Not supported | 2026-03-28 |
| Data source | .venv (installed packages) | 2026-03-28 |
| Markdown output | No (CycloneDX JSON/XML only) | 2026-03-28 |
| Upgrade paths | No | 2026-03-28 |
| Direct/transitive distinction | No (all packages equal) | 2026-03-28 |
| CVE checking | No (pure SBOM generation) | 2026-03-28 |

**Verification command:**
```bash
pip show cyclonedx-bom | grep Version
cyclonedx-py --help
```

**Key differentiator vs. uv-sbom:**
cyclonedx-python reads from the installed .venv, not uv.lock. This means it cannot
accurately distinguish direct from transitive dependencies, and its output reflects
what is installed rather than what the project declares.

**Watch for:**
- uv.lock reader support (would narrow our differentiation)
- Markdown output support (would narrow human-readability differentiation)

---

## pip-audit

| Attribute | Value | Last Verified |
|-----------|-------|--------------|
| Latest version | 2.7.x | 2026-03-28 |
| uv.lock support | Indirect (via requirements export) | 2026-03-28 |
| Data source | pip/requirements.txt or installed env | 2026-03-28 |
| Markdown output | No (plain text / JSON) | 2026-03-28 |
| Upgrade paths | No (lists CVEs only) | 2026-03-28 |
| Direct/transitive distinction | No | 2026-03-28 |
| CVE checking | Yes (OSV + PyPI advisory DB) | 2026-03-28 |

**Verification command:**
```bash
pip show pip-audit | grep Version
pip-audit --help
```

**Key differentiator vs. uv-sbom:**
pip-audit lists vulnerabilities but does not provide upgrade paths or distinguish
root-cause transitive issues from direct issues. Its uv.lock support requires
first exporting to requirements.txt, losing lock-file graph information.

**Watch for:**
- Native uv.lock support (Astral/uv project has been expanding ecosystem support)
- Upgrade advisor feature (direct competitor to our Resolution Guide)

---

## Syft (Anchore)

| Attribute | Value | Last Verified |
|-----------|-------|--------------|
| Latest version | 1.x | 2026-03-28 |
| uv.lock support | Limited (detects packages, not graph) | 2026-03-28 |
| Data source | Installed packages / image layers | 2026-03-28 |
| Markdown output | No (SBOM formats: CycloneDX, SPDX, etc.) | 2026-03-28 |
| Upgrade paths | No | 2026-03-28 |
| Direct/transitive distinction | No | 2026-03-28 |
| Target audience | Enterprise SBOM pipelines / containers | 2026-03-28 |

**Verification command:**
```bash
syft version
syft scan --help | grep "uv\|lock"
```

**Key differentiator vs. uv-sbom:**
Syft is a general-purpose SBOM generator for containers and code repos. It treats
all packages as equal (no direct/transitive distinction). It is not designed for
developer-facing readability or actionable output.

**Watch for:**
- uv.lock graph traversal (would narrow direct/transitive differentiation)
- Developer-facing Markdown output (unlikely given enterprise focus)

---

## Summary: Differentiation Status

| Feature | uv-sbom | cyclonedx-python | pip-audit | Syft |
|---------|---------|-----------------|-----------|------|
| uv.lock native support | ✅ | ❌ | ⚠️ indirect | ⚠️ limited |
| Human-readable Markdown | ✅ | ❌ | ❌ | ❌ |
| Upgrade Advisor | ✅ | ❌ | ❌ | ❌ |
| Direct/transitive distinction | ✅ | ❌ | ❌ | ❌ |
| CVE checking | ✅ | ❌ | ✅ | ❌ |
| Lock-file-based (not installed env) | ✅ | ❌ | ❌ | ❌ |

*Last updated: 2026-03-28*

---

## Update Log

| Date | Tool | Change | Updated by |
|------|------|--------|-----------|
| 2026-03-28 | All | Initial document created | Claude Code |
