# Competitive Landscape

Last full review: 2026-11-05
Review cadence: Update whenever a new version of a competing tool is released,
or when uv-sbom adds a feature that may change the competitive picture.

## How to use this file

This file is read during feature triage to determine whether a proposed feature is
differentiated from existing tools. Its consumers are `/ideate` Step 3 and
`.claude/feature-triage.md` (Step 1 Q4 and Step 3 D).

Before relying on any entry, check whether it is stale (last-verified date > 3 months ago).
If stale, run the verification command to update. Rows still dated 2026-03-28 were
carried over unchanged from the initial review and are known to be stale.

---

## Tracked tools

This section owns the list of tools and services that feature triage checks against.
Consumers link here and do not name tools themselves.

### Competitor tools

Check a proposed feature against each of these for "does it already offer this?" and
for differentiation (triage D).

| Tool | Section | Reads uv.lock |
|------|---------|---------------|
| uv (`uv audit`) | [uv (`uv audit`)](#uv-uv-audit) | ✅ native |
| pip-audit | [pip-audit](#pip-audit) | ❌ out of scope upstream |
| cyclonedx-python | [cyclonedx-python](#cyclonedx-python) | ❌ (venv only) |
| Syft / Grype | [Syft / Grype (Anchore)](#syft--grype-anchore) | ✅ (Syft cataloger; Grype unverified) |
| osv-scanner | [osv-scanner](#osv-scanner) | ✅ |
| Trivy | [Trivy](#trivy) | ✅ |

### Integrate, don't duplicate

Triage Q4 STOPs a feature that replicates the core purpose of one of these. uv-sbom
consumes or points to them instead.

| Service / tool | Why we integrate rather than duplicate |
|----------------|----------------------------------------|
| OSV (osv.dev) | Vulnerability database; uv-sbom queries it, never maintains its own advisory data |
| Dependency-Track | SBOM portfolio and continuous-monitoring platform; uv-sbom's CycloneDX output feeds it |
| pip-audit | Vulnerability auditing for pip / requirements.txt workflows; out of uv-sbom's uv.lock scope |

### Unverified

These tools may overlap with uv-sbom, but their uv behavior has not been verified from
an authoritative source. **Do not cite them in triage** until verified (tracked in #1062).

| Tool | Known (2026-11-05) | Still to verify |
|------|--------------------|-----------------|
| Dependabot | `uv` is a supported ecosystem ([source](https://docs.github.com/en/code-security/dependabot/ecosystems-supported-by-dependabot/supported-ecosystems-and-repositories)) | Security updates for transitive dependencies in uv.lock |
| Renovate | pep621 manager supports `uv.lock`; `lockFileMaintenance` uses the uv CLI ([source](https://docs.renovatebot.com/modules/manager/pep621/)) | Security updates for transitive dependencies in uv.lock |
| Safety CLI | Latest 3.8.1 (2026-05-29) ([source](https://pypi.org/project/safety/)) | Whether it scans uv.lock |

---

## uv (`uv audit`)

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | 0.13.7 (2026-11-03); `uv audit` available since 0.13.4 | 2026-11-05 | [releases](https://github.com/astral-sh/uv/releases) |
| uv.lock support | Native (uv owns the format) | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| CVE checking | Yes: OSV (`--service-format osv`, `--service-url`, default https://api.osv.dev/) | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| Status audit | Yes: "adverse" statuses such as deprecation and quarantine | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| Suppression | `--ignore`, `--ignore-until-fixed` (both match aliases) | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| Output formats | `text` (default), `json`, `sarif`; no Markdown | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| Direct/transitive distinction | No documented option (CLI reference only; source not checked) | 2026-11-05 | [CLI reference](https://docs.astral.sh/uv/reference/cli/#uv-audit) |
| Remediation / upgrade paths | No: `--fix` mode is unchecked on the roadmap; the proposal is `--upgrade-package`-based and open | 2026-11-05 | [uv#18506](https://github.com/astral-sh/uv/issues/18506), [uv#19428](https://github.com/astral-sh/uv/issues/19428) |
| Yanked flagging | No: "Flag yanked distributions" is unchecked on the roadmap; `uv sync` from a lockfile gives no yanked warning (`uv lock -P` does) | 2026-11-05 | [uv#18506](https://github.com/astral-sh/uv/issues/18506), [uv#19112](https://github.com/astral-sh/uv/issues/19112) |
| CycloneDX export | Yes, via `uv export` (separate from `uv audit`) | 2026-11-05 | [export docs](https://docs.astral.sh/uv/concepts/projects/export/#cyclonedx-sbom-format) |

**Verification command:**
```bash
uv --version
uv audit --help
gh issue view 18506 -R astral-sh/uv
```

**Key differentiator vs. uv-sbom:**
`uv audit` is the most direct competitor: it is built into uv, reads uv.lock natively,
and checks OSV vulnerabilities plus package statuses. It reports in terminal text,
JSON, or SARIF. It does not produce a human-readable Markdown report, attribute a
finding to the direct dependency that pulls it in, suggest verified upgrade paths, or
check licenses, abandoned packages, or Python compatibility.

**Watch for:**
- `uv audit --fix` (would overlap the Upgrade Advisor and `--incident` next action)
- Yanked-distribution flagging
- Markdown or other human-readable report output
- Direct/transitive attribution or dependency paths in findings

---

## pip-audit

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | 2.10.1 (2026-06-10) | 2026-11-05 | [PyPI](https://pypi.org/project/pip-audit/) |
| uv.lock support | Not planned: closed as out of scope, "uv has `uv audit`, which is the equivalent" | 2026-11-05 | [pip-audit#1077](https://github.com/pypa/pip-audit/issues/1077) |
| Data source | pip/requirements.txt or installed env | 2026-03-28 | — |
| Markdown output | No (plain text / JSON) | 2026-03-28 | — |
| Remediation / upgrade paths | `--fix` for requirements/env; transitive fixes not guaranteed | 2026-10-21 | [README](https://github.com/pypa/pip-audit#readme) |
| Direct/transitive distinction | No | 2026-03-28 | — |
| CVE checking | Yes (OSV + PyPI advisory DB) | 2026-03-28 | — |
| Yanked flagging | No: request still open | 2026-11-05 | [pip-audit#381](https://github.com/pypa/pip-audit/issues/381) |

**Verification command:**
```bash
pip show pip-audit | grep Version
pip-audit --help
gh issue view 1077 -R pypa/pip-audit
```

**Key differentiator vs. uv-sbom:**
pip-audit serves pip / requirements.txt workflows and has declined uv.lock support,
deferring to `uv audit`. It lists vulnerabilities without distinguishing root-cause
transitive issues from direct ones.

**Watch for:**
- Reversal of the uv.lock decision
- Yanked-package reporting (#381)

---

## cyclonedx-python

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | 8.0.1 (2026-11-04); 8.0.0 changed only the `environment` subcommand's interpreter probing | 2026-11-05 | [releases](https://github.com/CycloneDX/cyclonedx-python/releases) |
| uv.lock support | Not supported (uv lockfile "not explicitly supported", venv only). uv.lock requests closed, pointing to `uv export --format cyclonedx1.5` | 2026-11-05 (issues); README wording last verified 2026-10-21 | [#907](https://github.com/CycloneDX/cyclonedx-python/issues/907), [#1029](https://github.com/CycloneDX/cyclonedx-python/issues/1029), [README](https://github.com/CycloneDX/cyclonedx-python/blob/master/README.md) |
| Data source | .venv (installed packages) | 2026-03-28 | — |
| Markdown output | No (CycloneDX JSON/XML only) | 2026-03-28 | — |
| Upgrade paths | No | 2026-03-28 | — |
| Direct/transitive distinction | No (all packages equal) | 2026-03-28 | — |
| CVE checking | No (pure SBOM generation) | 2026-03-28 | — |

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
- uv itself exports CycloneDX (`uv export --format cyclonedx1.5`), which narrows the
  "CycloneDX from uv.lock" niche, though not the human-readable Markdown one.
  Issue-comment reports on #1029/#907 (hardcoded spec version, no `licenses`, possibly
  missing dependency edges) are third-party and unverified against current uv.
- Any reversal of the uv.lock decision

---

## Syft / Grype (Anchore)

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | Syft 1.56.0 / Grype 0.121.1 (2026-11-02) | 2026-11-05 | [Syft releases](https://github.com/anchore/syft/releases), [Grype releases](https://github.com/anchore/grype/releases) |
| uv.lock support | Syft: uv.lock cataloger (added 2025-07-17; dependents linked to locked version since 2026-09-29). Grype: unverified | 2026-11-05 | [syft#3268](https://github.com/anchore/syft/issues/3268) |
| Data source | Lock files / installed packages / image layers | 2026-11-05 | [syft#3268](https://github.com/anchore/syft/issues/3268) |
| Markdown output | No (SBOM formats: CycloneDX, SPDX, etc.) | 2026-03-28 | — |
| Upgrade paths | Not verified (none found in 2026-10-21 research) | — | — |
| Yanked flagging | Not verified (none found in 2026-10-21 research) | — | — |
| Direct/transitive distinction | No | 2026-03-28 | — |
| CVE checking | Syft no; Grype yes | 2026-03-28 | — |
| Target audience | Enterprise SBOM pipelines / containers | 2026-03-28 | — |

**Verification command:**
```bash
syft version
grype version
syft scan --help | grep "uv\|lock"
```

**Key differentiator vs. uv-sbom:**
Syft is a general-purpose SBOM generator for containers and code repos. Its uv.lock
cataloger reads packages, but its output treats all packages as equal (no
direct/transitive distinction in findings) and is not designed for developer-facing
readability or actionable output.

**Watch for:**
- Direct/transitive attribution in Grype findings
- Developer-facing Markdown output (unlikely given enterprise focus)

---

## osv-scanner

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | 2.7.0 (2026-10-12) | 2026-11-05 | [releases](https://github.com/google/osv-scanner/releases) |
| uv.lock support | Yes | 2026-11-05 | [supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) |
| CVE checking | Yes (OSV) | 2026-11-05 | [supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) |
| Remediation | Guided remediation (`osv-scanner fix`, experimental) supports npm and Maven only; no Python | 2026-11-05 | [guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/) |
| Markdown output | Not verified | — | — |

**Verification command:**
```bash
osv-scanner --version
osv-scanner scan source --help
```

**Key differentiator vs. uv-sbom:**
osv-scanner is a multi-ecosystem vulnerability scanner that reads uv.lock. It has no
Python remediation, no upgrade-path verification, and no license / abandoned /
compatibility checks.

**Watch for:**
- Guided remediation for Python / uv.lock (would overlap the Upgrade Advisor)

---

## Trivy

| Attribute | Value | Last Verified | Source |
|-----------|-------|--------------|--------|
| Latest version | 0.76.1 (2026-10-21) | 2026-11-05 | [releases](https://github.com/aquasecurity/trivy/releases) |
| uv.lock support | Yes: "Trivy uses uv.lock to identify dependencies and find vulnerabilities"; transitive deps and dependency graph supported; dev deps excluded by default | 2026-11-05 | [Python coverage](https://trivy.dev/latest/docs/coverage/language/python/) |
| License detection for uv | Not supported | 2026-11-05 | [Python coverage](https://trivy.dev/latest/docs/coverage/language/python/) |
| Remediation | Not verified (none found in 2026-10-21 research) | — | — |

**Verification command:**
```bash
trivy --version
```

**Key differentiator vs. uv-sbom:**
Trivy is a general-purpose security scanner (containers, IaC, languages). It finds
vulnerabilities from uv.lock but offers no remediation and no license data for uv.

**Watch for:**
- Remediation or license detection for uv projects

---

## Summary: Differentiation Status

| Feature | uv-sbom | uv audit | pip-audit | cyclonedx-python | Syft / Grype | osv-scanner | Trivy |
|---------|---------|----------|-----------|-----------------|--------------|-------------|-------|
| uv.lock native support | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Human-readable Markdown | ✅ | ❌ | ❌ | ❌ | ❌ | — | — |
| Upgrade Advisor | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Remediation for uv projects | ✅ | ❌ (`--fix` planned) | ❌ | ❌ | — | ❌ (npm/Maven only) | — |
| Direct/transitive distinction | ✅ | ❌ | ❌ | ❌ | ❌ | — | — |
| CVE checking | ✅ | ✅ | ✅ | ❌ | ⚠️ Grype only | ✅ | ✅ |
| Lock-file-based (not installed env) | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Yanked flagging | ❌ (planned, #957) | ❌ (planned) | ❌ | ❌ | — | — | — |

`—` means not verified. ❌ for Direct/transitive distinction outside uv-sbom means no
documented option, as of 2026-11-05.

*Last updated: 2026-11-05*

---

## Update Log

| Date | Tool | Change | Updated by |
|------|------|--------|-----------|
| 2026-03-28 | All | Initial document created | Claude Code |
| 2026-11-05 | All | Full refresh (research 2026-10-21, re-verified 2026-11-05); added uv audit, osv-scanner, Trivy; tracked-tools list | Claude Code |
