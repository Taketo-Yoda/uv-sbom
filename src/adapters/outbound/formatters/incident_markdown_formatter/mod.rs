//! Markdown formatter for `--incident` reports (#967). The workspace layout
//! (#969) lives in `workspace.rs` and reuses the section helpers here.

mod workspace;

use crate::application::read_models::incident_report::{
    IncidentFinding, IncidentGuidance, IncidentReport, IncidentSource, IncidentVerdictView,
    ReleaseStatusView,
};
use crate::application::read_models::vulnerability_view::SeverityView;
use crate::i18n::{Locale, Messages};

/// The advisory fields shown in the heading block, shared by the
/// single-project and workspace layouts.
struct HeadingFields<'a> {
    advisory_id: &'a str,
    source: IncidentSource,
    resolved_from: Option<&'a str>,
    aliases: &'a [String],
    severity: Option<SeverityView>,
    summary: Option<&'a str>,
    overall: IncidentVerdictView,
}

impl<'a> From<&'a IncidentReport> for HeadingFields<'a> {
    fn from(report: &'a IncidentReport) -> Self {
        Self {
            advisory_id: &report.advisory_id,
            source: report.source,
            resolved_from: report.resolved_from.as_deref(),
            aliases: &report.aliases,
            severity: report.severity,
            summary: report.summary.as_deref(),
            overall: report.overall,
        }
    }
}

/// Formats an `IncidentReport` as a human-readable Markdown report (#967).
///
/// Layout: a heading block (advisory ID, optional "resolved from" line,
/// aliases, severity, summary, overall verdict; for a manual range spec, #963,
/// the spec and a "not verified" notice instead), then three numbered sections
/// in order — `1. Impact`, `2. Patch status`, `3. Next action`. Section 3 is
/// omitted when the overall verdict is "not affected". Every label comes from
/// `Messages`, so `--lang ja` output is fully localized; commands stay
/// untranslated so they remain copy-pasteable.
pub struct IncidentMarkdownFormatter {
    messages: &'static Messages,
}

impl IncidentMarkdownFormatter {
    /// Creates a new `IncidentMarkdownFormatter` for the given locale.
    pub fn new(locale: Locale) -> Self {
        Self {
            messages: Messages::for_locale(locale),
        }
    }

    /// Formats `report` as a Markdown string. This operation is infallible.
    ///
    /// Advisory text from OSV (advisory ID, resolved-from ID, aliases,
    /// summary, affected package names) and adapter error reasons are
    /// untrusted, so they are collapsed onto a single line before rendering.
    pub fn format(&self, report: &IncidentReport) -> String {
        let mut lines: Vec<String> = Vec::new();
        self.push_heading(&mut lines, report.into());
        self.push_impact(&mut lines, report);
        self.push_patch_status(
            &mut lines,
            &report.findings,
            report.source,
            self.messages.incident_status_not_applicable,
        );
        if report.overall != IncidentVerdictView::NotAffected {
            self.push_next_action(&mut lines, &report.findings);
        }
        finish(lines)
    }

    fn push_heading(&self, lines: &mut Vec<String>, report: HeadingFields<'_>) {
        let msgs = self.messages;
        if report.source == IncidentSource::Manual {
            self.push_manual_heading(lines, &report);
            return;
        }
        lines.push(Messages::format(
            msgs.incident_title,
            &[&single_line(report.advisory_id)],
        ));
        if let Some(from) = report.resolved_from {
            lines.push(Messages::format(
                msgs.incident_resolved_from,
                &[&single_line(from)],
            ));
        }
        lines.push(String::new());

        if !report.aliases.is_empty() {
            let aliases: Vec<String> = report.aliases.iter().map(|a| single_line(a)).collect();
            lines.push(format!(
                "- **{}**: {}",
                msgs.incident_label_aliases,
                aliases.join(", ")
            ));
        }
        if let Some(severity) = report.severity {
            lines.push(format!(
                "- **{}**: {}",
                msgs.incident_label_severity,
                severity.as_str()
            ));
        }
        if let Some(summary) = report.summary {
            lines.push(format!(
                "- **{}**: {}",
                msgs.incident_label_summary,
                single_line(summary)
            ));
        }
        lines.push(format!(
            "- **{}**: {}",
            msgs.incident_label_overall,
            self.verdict_label(report.overall)
        ));
        lines.push(String::new());
    }

    /// Heading for a user-supplied range spec (#963): the spec in a code span
    /// (so `<` and `>=` are not read as markup), the "not verified" notice,
    /// and the overall verdict. A spec that parsed contains no backtick.
    fn push_manual_heading(&self, lines: &mut Vec<String>, report: &HeadingFields<'_>) {
        let msgs = self.messages;
        lines.push(Messages::format(
            msgs.incident_title_manual,
            &[&single_line(report.advisory_id)],
        ));
        lines.push(String::new());
        lines.push(msgs.incident_manual_notice.to_string());
        lines.push(String::new());
        lines.push(format!(
            "- **{}**: {}",
            msgs.incident_label_overall,
            self.verdict_label(report.overall)
        ));
        lines.push(String::new());
    }

    fn push_impact(&self, lines: &mut Vec<String>, report: &IncidentReport) {
        let msgs = self.messages;
        lines.push(msgs.incident_section_impact.to_string());
        lines.push(String::new());

        if report.affected_packages.is_empty() {
            lines.push(msgs.incident_no_pypi_package.to_string());
        } else if report.findings.is_empty() {
            lines.push(Messages::format(
                msgs.incident_packages_not_in_project,
                &[&single_line(&report.affected_packages.join(", "))],
            ));
        } else {
            self.push_finding_lines(lines, &report.findings);
        }
        lines.push(String::new());
    }

    /// One bullet per finding (package, version, verdict, position), followed
    /// by its dependency paths.
    fn push_finding_lines(&self, lines: &mut Vec<String>, findings: &[IncidentFinding]) {
        let msgs = self.messages;
        for finding in findings {
            let position = if finding.is_direct {
                msgs.incident_dependency_direct
            } else {
                msgs.incident_dependency_transitive
            };
            lines.push(format!(
                "- **{}** {} — {} ({})",
                finding.package_name,
                finding.locked_version,
                self.verdict_label(finding.verdict),
                position
            ));
            if !finding.paths.is_empty() {
                lines.push(format!("  - {}", msgs.incident_paths_label));
                for path in &finding.paths {
                    lines.push(format!("    - `{}`", path.join(" → ")));
                }
            } else if !finding.is_direct {
                lines.push(format!("  - {}", msgs.incident_no_path));
            }
        }
    }

    /// `not_applicable` is shown when there are no findings at all.
    fn push_patch_status(
        &self,
        lines: &mut Vec<String>,
        findings: &[IncidentFinding],
        source: IncidentSource,
        not_applicable: &str,
    ) {
        let msgs = self.messages;
        lines.push(msgs.incident_section_patch_status.to_string());
        lines.push(String::new());

        if findings.is_empty() {
            lines.push(not_applicable.to_string());
        } else {
            for finding in findings {
                lines.push(format!(
                    "- **{}**: {}",
                    finding.package_name,
                    self.patch_status(finding, source)
                ));
            }
        }
        lines.push(String::new());
    }

    fn push_next_action(&self, lines: &mut Vec<String>, findings: &[IncidentFinding]) {
        let msgs = self.messages;
        lines.push(msgs.incident_section_next_action.to_string());
        lines.push(String::new());

        // Several locked versions of one package can share the same action;
        // render each distinct block once.
        let mut blocks: Vec<Vec<String>> = Vec::new();
        for finding in findings
            .iter()
            .filter(|f| f.verdict != IncidentVerdictView::NotAffected)
        {
            let block = self.next_action_block(finding);
            if !block.is_empty() && !blocks.contains(&block) {
                blocks.push(block);
            }
        }
        for block in blocks {
            lines.extend(block);
            lines.push(String::new());
        }
    }

    fn next_action_block(&self, finding: &IncidentFinding) -> Vec<String> {
        let msgs = self.messages;
        let name = finding.package_name.as_str();
        let fixed = finding.fixed_version.as_deref().unwrap_or_default();

        if let Some(command) = &finding.upgrade_command {
            let label = if finding.command_verified {
                msgs.incident_action_verified
            } else {
                msgs.incident_action_not_verified
            };
            return vec![
                format!("**{}** — {}", name, label),
                "```sh".to_string(),
                command.clone(),
                "uv sync".to_string(),
                "```".to_string(),
            ];
        }

        let guidance = match &finding.guidance {
            Some(IncidentGuidance::ResolutionBlocked { direct_roots }) => Messages::format(
                msgs.incident_guidance_resolution_blocked,
                &[name, fixed, &direct_roots.join(", ")],
            ),
            Some(IncidentGuidance::NoReleasedFix) => {
                Messages::format(msgs.incident_guidance_no_released_fix, &[name])
            }
            Some(IncidentGuidance::SimulationError { reason }) => Messages::format(
                msgs.incident_guidance_simulation_error,
                &[name, fixed, &single_line(reason)],
            ),
            Some(IncidentGuidance::ReleaseLookupFailed { reason }) => Messages::format(
                msgs.incident_guidance_release_lookup_failed,
                &[name, fixed, &single_line(reason)],
            ),
            Some(IncidentGuidance::NotFromPyPi) => {
                Messages::format(msgs.incident_guidance_not_from_pypi, &[name, fixed])
            }
            None => return Vec::new(),
        };
        vec![guidance]
    }

    fn patch_status(&self, finding: &IncidentFinding, source: IncidentSource) -> String {
        let msgs = self.messages;
        let Some(fixed) = &finding.fixed_version else {
            return match (finding.verdict, source) {
                (IncidentVerdictView::NotAffected, _) => msgs.incident_status_not_applicable,
                (_, IncidentSource::Osv) => msgs.incident_status_no_fixed_version,
                (_, IncidentSource::Manual) => msgs.incident_status_no_fixed_version_manual,
            }
            .to_string();
        };
        let status = match finding.release_status {
            Some(ReleaseStatusView::Released) => msgs.incident_status_released,
            Some(ReleaseStatusView::Yanked) => msgs.incident_status_yanked,
            Some(ReleaseStatusView::NotFound) => msgs.incident_status_not_found,
            None if finding.guidance == Some(IncidentGuidance::NotFromPyPi) => {
                msgs.incident_status_not_from_pypi
            }
            None => msgs.incident_status_unknown,
        };
        format!(
            "{} — {}",
            Messages::format(msgs.incident_status_fixed_in, &[fixed]),
            status
        )
    }

    fn verdict_label(&self, verdict: IncidentVerdictView) -> &'static str {
        let msgs = self.messages;
        match verdict {
            IncidentVerdictView::NotAffected => msgs.incident_verdict_not_affected,
            IncidentVerdictView::AffectedFixReleased => msgs.incident_verdict_fix_released,
            IncidentVerdictView::AffectedFixUnreleased => msgs.incident_verdict_fix_unreleased,
            IncidentVerdictView::AffectedNoFix => msgs.incident_verdict_no_fix,
        }
    }
}

/// Drops trailing blank lines and joins `lines` with a final newline.
fn finish(mut lines: Vec<String>) -> String {
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Collapses all whitespace runs (including newlines) in untrusted text to a
/// single space, so it cannot break out of its Markdown line.
fn single_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn finding(verdict: IncidentVerdictView) -> IncidentFinding {
        IncidentFinding {
            package_name: "requests".to_string(),
            locked_version: "2.25.0".to_string(),
            is_direct: true,
            paths: vec![],
            fixed_version: Some("2.31.0".to_string()),
            release_status: Some(ReleaseStatusView::Released),
            verdict,
            upgrade_command: None,
            command_verified: false,
            guidance: None,
        }
    }

    pub(super) fn verified() -> IncidentFinding {
        IncidentFinding {
            upgrade_command: Some("uv lock --upgrade-package requests==2.31.0".to_string()),
            command_verified: true,
            ..finding(IncidentVerdictView::AffectedFixReleased)
        }
    }

    pub(super) fn report(findings: Vec<IncidentFinding>) -> IncidentReport {
        let overall = findings
            .iter()
            .map(|f| f.verdict)
            .find(|v| *v != IncidentVerdictView::NotAffected)
            .unwrap_or(IncidentVerdictView::NotAffected);
        IncidentReport {
            advisory_id: "GHSA-j8r2-6x86-q33q".to_string(),
            source: IncidentSource::Osv,
            resolved_from: None,
            aliases: vec!["CVE-2023-32681".to_string(), "PYSEC-2023-74".to_string()],
            severity: Some(SeverityView::Medium),
            summary: Some("Unintended leak of\nProxy-Authorization header".to_string()),
            affected_packages: vec!["requests".to_string()],
            findings,
            overall,
        }
    }

    fn en(report: &IncidentReport) -> String {
        IncidentMarkdownFormatter::new(Locale::En).format(report)
    }

    fn ja(report: &IncidentReport) -> String {
        IncidentMarkdownFormatter::new(Locale::Ja).format(report)
    }

    pub(super) fn position(out: &str, needle: &str) -> usize {
        out.find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in:\n{out}"))
    }

    #[test]
    fn test_verified_command_full_layout_en() {
        let out = en(&report(vec![verified()]));

        let expected = "\
## Incident Report: GHSA-j8r2-6x86-q33q

- **Aliases**: CVE-2023-32681, PYSEC-2023-74
- **Severity**: MEDIUM
- **Summary**: Unintended leak of Proxy-Authorization header
- **Overall verdict**: Affected — fix released

### 1. Impact

- **requests** 2.25.0 — Affected — fix released (direct dependency)

### 2. Patch status

- **requests**: fixed in 2.31.0 — released

### 3. Next action

**requests** — Verified by a dry-run resolution (your uv.lock was not modified):
```sh
uv lock --upgrade-package requests==2.31.0
uv sync
```
";
        assert_eq!(out, expected);
    }

    #[test]
    fn test_section_order_heading_then_1_2_3() {
        let out = en(&report(vec![verified()]));

        let heading = position(&out, "## Incident Report");
        let impact = position(&out, "### 1. Impact");
        let patch = position(&out, "### 2. Patch status");
        let next = position(&out, "### 3. Next action");
        assert!(heading < impact && impact < patch && patch < next);
    }

    #[test]
    fn test_resolved_from_line_and_omitted_severity() {
        let mut r = report(vec![verified()]);
        r.resolved_from = Some("CVE-2023-32681".to_string());
        r.severity = None;

        let out = en(&r);

        assert!(out.starts_with(
            "## Incident Report: GHSA-j8r2-6x86-q33q\n(resolved from CVE-2023-32681)\n"
        ));
        assert!(!out.contains("**Severity**"));
    }

    #[test]
    fn test_transitive_paths_rendered_with_arrows() {
        let f = IncidentFinding {
            is_direct: false,
            paths: vec![vec![
                "flask".to_string(),
                "werkzeug".to_string(),
                "requests".to_string(),
            ]],
            ..verified()
        };

        let out = en(&report(vec![f]));

        assert!(out.contains(
            "- **requests** 2.25.0 — Affected — fix released (transitive dependency)\n  - Dependency path(s):\n    - `flask → werkzeug → requests`\n"
        ));
    }

    #[test]
    fn test_transitive_without_path_shows_no_path_note() {
        let f = IncidentFinding {
            is_direct: false,
            ..verified()
        };

        let out = en(&report(vec![f]));

        assert!(out.contains("  - No path from the project's main dependencies"));
    }

    #[test]
    fn test_unverified_command_en() {
        let f = IncidentFinding {
            command_verified: false,
            ..verified()
        };

        let out = en(&report(vec![f]));

        assert!(out.contains("**requests** — ⚠️ Not verified (uv is not available)"));
        assert!(out.contains("```sh\nuv lock --upgrade-package requests==2.31.0\nuv sync\n```"));
    }

    #[test]
    fn test_resolution_blocked_guidance_en() {
        let f = IncidentFinding {
            guidance: Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["flask".to_string(), "httpx".to_string()],
            }),
            ..finding(IncidentVerdictView::AffectedFixReleased)
        };

        let out = en(&report(vec![f]));

        assert!(out.contains(
            "Upgrading **requests** to 2.31.0 could not be resolved. The blocking constraint is likely held by: flask, httpx. Run `uv-sbom --suggest-fix` to find compatible upgrades."
        ));
        assert!(!out.contains("```sh"));
    }

    #[test]
    fn test_unreleased_statuses_en() {
        for (status, label) in [
            (Some(ReleaseStatusView::NotFound), "not published on PyPI"),
            (Some(ReleaseStatusView::Yanked), "yanked"),
            (None, "release status unknown (lookup failed)"),
        ] {
            let f = IncidentFinding {
                release_status: status,
                guidance: Some(IncidentGuidance::NoReleasedFix),
                ..finding(IncidentVerdictView::AffectedFixUnreleased)
            };

            let out = en(&report(vec![f]));

            assert!(out.contains(&format!("- **requests**: fixed in 2.31.0 — {label}")));
            assert!(out.contains("No released fix is available for **requests** yet."));
            assert!(out.contains("Affected — fix not yet released"));
        }
    }

    #[test]
    fn test_no_fix_en() {
        let f = IncidentFinding {
            fixed_version: None,
            release_status: None,
            guidance: Some(IncidentGuidance::NoReleasedFix),
            ..finding(IncidentVerdictView::AffectedNoFix)
        };

        let out = en(&report(vec![f]));

        assert!(out.contains("Affected — no fix available"));
        assert!(out.contains("- **requests**: the advisory names no fixed version"));
        assert!(out.contains("No released fix is available for **requests** yet."));
    }

    #[test]
    fn test_simulation_error_en() {
        let f = IncidentFinding {
            guidance: Some(IncidentGuidance::SimulationError {
                reason: "uv timed\nout".to_string(),
            }),
            ..finding(IncidentVerdictView::AffectedFixReleased)
        };

        let out = en(&report(vec![f]));

        assert!(out.contains("Could not verify an upgrade of **requests** to 2.31.0: uv timed out"));
    }

    #[test]
    fn test_release_lookup_failed_en() {
        let f = IncidentFinding {
            release_status: None,
            guidance: Some(IncidentGuidance::ReleaseLookupFailed {
                reason: "connection\nreset".to_string(),
            }),
            ..finding(IncidentVerdictView::AffectedFixUnreleased)
        };

        let out = en(&report(vec![f]));

        assert!(out
            .contains("- **requests**: fixed in 2.31.0 — release status unknown (lookup failed)"));
        assert!(out.contains(
            "Could not check whether **requests** 2.31.0 is released: connection reset. Check PyPI manually before upgrading."
        ));
        assert!(!out.contains("No released fix"));
    }

    #[test]
    fn test_not_from_pypi_en() {
        let f = IncidentFinding {
            release_status: None,
            guidance: Some(IncidentGuidance::NotFromPyPi),
            ..finding(IncidentVerdictView::AffectedFixUnreleased)
        };

        let out = en(&report(vec![f]));

        assert!(out.contains(
            "- **requests**: fixed in 2.31.0 — not hosted on PyPI — release status not checked"
        ));
        assert!(out.contains(
            "**requests** is not installed from PyPI; check its source for a release containing the fix (2.31.0)."
        ));
        assert!(!out.contains("lookup failed"));
        assert!(!out.contains("No released fix"));
    }

    #[test]
    fn test_untrusted_advisory_text_is_single_line() {
        let mut r = report(vec![]);
        r.advisory_id = "GHSA-x\n## injected".to_string();
        r.resolved_from = Some("CVE-1\n- fake".to_string());
        r.affected_packages = vec!["requests\n### x".to_string(), "urllib3".to_string()];

        let out = en(&r);

        assert!(out
            .starts_with("## Incident Report: GHSA-x ## injected\n(resolved from CVE-1 - fake)\n"));
        assert!(out.contains("None of the affected packages (requests ### x, urllib3)"));
        assert!(!out.contains("\n## injected"));
        assert!(!out.contains("\n### x"));
    }

    #[test]
    fn test_not_affected_present_keeps_sections_1_and_2_only() {
        let f = IncidentFinding {
            locked_version: "2.31.0".to_string(),
            fixed_version: None,
            release_status: None,
            ..finding(IncidentVerdictView::NotAffected)
        };

        let out = en(&report(vec![f]));

        assert!(out.contains("- **Overall verdict**: Not affected"));
        assert!(out.contains("- **requests** 2.31.0 — Not affected (direct dependency)"));
        assert!(out.contains("- **requests**: Not applicable — this project is not affected."));
        assert!(out.contains("### 2. Patch status"));
        assert!(!out.contains("### 3. Next action"));
    }

    #[test]
    fn test_not_affected_absent_lists_affected_packages() {
        let mut r = report(vec![]);
        r.affected_packages = vec!["requests".to_string(), "urllib3".to_string()];

        let out = en(&r);

        assert!(
            out.contains("None of the affected packages (requests, urllib3) are in this project.")
        );
        assert!(
            out.contains("### 2. Patch status\n\nNot applicable — this project is not affected.")
        );
        assert!(!out.contains("### 3. Next action"));
    }

    #[test]
    fn test_no_pypi_package_en() {
        let mut r = report(vec![]);
        r.affected_packages = vec![];

        let out = en(&r);

        assert!(out.contains("This advisory does not affect any PyPI package."));
        assert!(!out.contains("### 3. Next action"));
    }

    #[test]
    fn test_duplicate_actions_rendered_once() {
        let older = IncidentFinding {
            locked_version: "2.20.0".to_string(),
            ..verified()
        };

        let out = en(&report(vec![older, verified()]));

        assert_eq!(out.matches("```sh").count(), 1);
    }

    #[test]
    fn test_verified_command_ja_fully_localized() {
        let mut r = report(vec![verified()]);
        r.resolved_from = Some("CVE-2023-32681".to_string());

        let out = ja(&r);

        for needle in [
            "## インシデントレポート: GHSA-j8r2-6x86-q33q",
            "（CVE-2023-32681 から解決）",
            "- **別名**: ",
            "- **深刻度**: MEDIUM",
            "- **概要**: ",
            "- **総合判定**: 影響あり — 修正版リリース済み",
            "### 1. 影響",
            "(直接依存)",
            "### 2. パッチ状況",
            "- **requests**: 2.31.0 で修正 — リリース済み",
            "### 3. 次のアクション",
            "試行解決で検証済み（uv.lock は変更されていません）:",
            "uv lock --upgrade-package requests==2.31.0\nuv sync",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
        assert_no_english_labels(&out);
    }

    #[test]
    fn test_other_verdicts_ja_fully_localized() {
        let cases = vec![
            IncidentFinding {
                command_verified: false,
                ..verified()
            },
            IncidentFinding {
                is_direct: false,
                guidance: Some(IncidentGuidance::ResolutionBlocked {
                    direct_roots: vec!["flask".to_string()],
                }),
                ..finding(IncidentVerdictView::AffectedFixReleased)
            },
            IncidentFinding {
                release_status: Some(ReleaseStatusView::Yanked),
                guidance: Some(IncidentGuidance::NoReleasedFix),
                ..finding(IncidentVerdictView::AffectedFixUnreleased)
            },
            IncidentFinding {
                release_status: Some(ReleaseStatusView::NotFound),
                guidance: Some(IncidentGuidance::NoReleasedFix),
                ..finding(IncidentVerdictView::AffectedFixUnreleased)
            },
            IncidentFinding {
                release_status: None,
                guidance: Some(IncidentGuidance::NoReleasedFix),
                ..finding(IncidentVerdictView::AffectedFixUnreleased)
            },
            IncidentFinding {
                fixed_version: None,
                release_status: None,
                guidance: Some(IncidentGuidance::NoReleasedFix),
                ..finding(IncidentVerdictView::AffectedNoFix)
            },
            IncidentFinding {
                guidance: Some(IncidentGuidance::SimulationError {
                    reason: "boom".to_string(),
                }),
                ..finding(IncidentVerdictView::AffectedFixReleased)
            },
            IncidentFinding {
                fixed_version: None,
                release_status: None,
                ..finding(IncidentVerdictView::NotAffected)
            },
        ];
        for f in cases {
            let out = ja(&report(vec![f]));
            assert!(out.contains("### 1. 影響"), "{out}");
            assert!(out.contains("### 2. パッチ状況"), "{out}");
            assert_no_english_labels(&out);
        }

        let mut absent = report(vec![]);
        let out = ja(&absent);
        assert!(
            out.contains("影響対象パッケージ（requests）はこのプロジェクトに含まれていません。")
        );
        assert!(out.contains("該当なし — このプロジェクトは影響を受けません。"));
        assert_no_english_labels(&out);

        absent.affected_packages = vec![];
        let out = ja(&absent);
        assert!(out.contains("このアドバイザリは PyPI パッケージに影響しません。"));
        assert_no_english_labels(&out);
    }

    #[test]
    fn test_ja_release_lookup_failed_and_not_from_pypi() {
        let failed = IncidentFinding {
            release_status: None,
            guidance: Some(IncidentGuidance::ReleaseLookupFailed {
                reason: "timeout".to_string(),
            }),
            ..finding(IncidentVerdictView::AffectedFixUnreleased)
        };
        let out = ja(&report(vec![failed]));
        assert!(out.contains("**requests** 2.31.0 のリリース状況を確認できませんでした: timeout。更新前に PyPI を手動で確認してください。"));
        assert_no_english_labels(&out);

        let not_pypi = IncidentFinding {
            release_status: None,
            guidance: Some(IncidentGuidance::NotFromPyPi),
            ..finding(IncidentVerdictView::AffectedFixUnreleased)
        };
        let out = ja(&report(vec![not_pypi]));
        assert!(out
            .contains("- **requests**: 2.31.0 で修正 — PyPI 以外のソース — リリース状況は未確認"));
        assert!(out.contains(
            "**requests** は PyPI 以外からインストールされています。修正（2.31.0）を含むリリースをソース側で確認してください。"
        ));
        assert_no_english_labels(&out);
    }

    #[test]
    fn test_ja_guidance_strings() {
        let blocked = IncidentFinding {
            guidance: Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["flask".to_string()],
            }),
            ..finding(IncidentVerdictView::AffectedFixReleased)
        };
        assert!(ja(&report(vec![blocked])).contains(
            "**requests** を 2.31.0 へ更新できませんでした。制約を保持している可能性が高い直接依存: flask。`uv-sbom --suggest-fix` で互換性のある更新を確認してください。"
        ));

        let unverified = IncidentFinding {
            command_verified: false,
            ..verified()
        };
        assert!(ja(&report(vec![unverified]))
            .contains("⚠️ 未検証（uv を利用できません）— 実行前に確認してください:"));
    }

    pub(super) fn manual_report(findings: Vec<IncidentFinding>) -> IncidentReport {
        IncidentReport {
            advisory_id: "requests<2.31.0".to_string(),
            source: IncidentSource::Manual,
            resolved_from: None,
            aliases: vec![],
            severity: None,
            summary: None,
            ..report(findings)
        }
    }

    #[test]
    fn test_manual_source_heading_and_notice_en() {
        let out = en(&manual_report(vec![verified()]));

        let expected_heading = "\
## Incident Report (manual range): `requests<2.31.0`

⚠️ This affected range was supplied by you. It is not taken from a vulnerability database and has not been verified.

- **Overall verdict**: Affected — fix released

### 1. Impact
";
        assert!(out.starts_with(expected_heading), "{out}");
        for label in [
            "**Aliases**",
            "**Severity**",
            "**Summary**",
            "resolved from",
        ] {
            assert!(!out.contains(label), "manual output contains {label:?}");
        }
        assert!(out.contains("uv lock --upgrade-package requests==2.31.0"));
    }

    #[test]
    fn test_manual_source_no_fix_names_supplied_range() {
        let f = IncidentFinding {
            fixed_version: None,
            release_status: None,
            guidance: Some(IncidentGuidance::NoReleasedFix),
            ..finding(IncidentVerdictView::AffectedNoFix)
        };

        let out = en(&manual_report(vec![f]));

        assert!(out.contains("- **requests**: the supplied range names no fixed version"));
        assert!(!out.contains("the advisory names"));
    }

    #[test]
    fn test_manual_source_ja_fully_localized() {
        let out = ja(&manual_report(vec![verified()]));

        assert!(out.starts_with("## インシデントレポート（手動指定の範囲）: `requests<2.31.0`\n"));
        assert!(out.contains(
            "⚠️ この影響範囲はユーザーが指定したものです。脆弱性データベースの記録ではなく、検証もされていません。"
        ));
        assert_no_english_labels(&out);
        for label in ["manual range", "supplied by you"] {
            assert!(!out.contains(label), "JA output contains {label:?}:\n{out}");
        }
    }

    /// Every English label the formatter can emit; none may appear in JA output.
    pub(super) fn assert_no_english_labels(out: &str) {
        let en = Messages::for_locale(Locale::En);
        for label in [
            "Incident Report",
            "resolved from",
            en.incident_label_aliases,
            en.incident_label_severity,
            en.incident_label_summary,
            en.incident_label_overall,
            "Impact",
            "Patch status",
            "Next action",
            "Not affected",
            "Affected",
            en.incident_dependency_direct,
            en.incident_dependency_transitive,
            en.incident_paths_label,
            "No path",
            "fixed in",
            "released",
            "yanked —",
            "not published",
            "unknown",
            "names no fixed version",
            "Not applicable",
            "Verified",
            "Not verified",
            "could not be resolved",
            "No released fix",
            "Could not verify",
            "Could not check",
            "not installed from PyPI",
            "not hosted on PyPI",
            "not checked",
        ] {
            assert!(!out.contains(label), "JA output contains {label:?}:\n{out}");
        }
    }
}
