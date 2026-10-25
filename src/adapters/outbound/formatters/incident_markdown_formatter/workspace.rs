//! Workspace layout for `--incident --workspace` (#969).

use super::{finish, single_line, HeadingFields, IncidentMarkdownFormatter};
use crate::application::read_models::incident_report::{
    IncidentVerdictView, WorkspaceIncidentReport,
};
use crate::i18n::Messages;

impl<'a> From<&'a WorkspaceIncidentReport> for HeadingFields<'a> {
    fn from(report: &'a WorkspaceIncidentReport) -> Self {
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

impl IncidentMarkdownFormatter {
    /// Formats a workspace report (#969) as one Markdown report: the shared
    /// heading block, `1. Impact` with one subsection per member (its verdict
    /// and paths), `2. Patch status` and `3. Next action` built from the
    /// findings deduplicated across members (the fix and the command are the
    /// same for every member), and a final "N of M members affected" line.
    /// Section 3 is omitted when no member is affected. Infallible.
    pub fn format_workspace(&self, report: &WorkspaceIncidentReport) -> String {
        let msgs = self.messages;
        let mut lines: Vec<String> = Vec::new();
        self.push_heading(&mut lines, report.into());

        lines.push(msgs.incident_section_impact.to_string());
        lines.push(String::new());
        for member in &report.members {
            lines.push(Messages::format(
                msgs.incident_member_heading,
                &[&single_line(&member.name)],
            ));
            lines.push(String::new());
            lines.push(format!(
                "- **{}**: {}",
                msgs.incident_label_member_verdict,
                self.verdict_label(member.overall)
            ));
            // A paragraph needs a blank line, or Markdown folds it into the
            // verdict bullet above.
            if report.affected_packages.is_empty() {
                lines.push(String::new());
                lines.push(msgs.incident_no_pypi_package.to_string());
            } else if member.findings.is_empty() {
                lines.push(String::new());
                lines.push(Messages::format(
                    msgs.incident_packages_not_in_member,
                    &[&single_line(&report.affected_packages.join(", "))],
                ));
            } else {
                self.push_finding_lines(&mut lines, &member.findings);
            }
            lines.push(String::new());
        }

        let findings = report.deduplicated_findings();
        self.push_patch_status(
            &mut lines,
            &findings,
            report.source,
            msgs.incident_status_not_applicable_workspace,
        );
        if report.overall != IncidentVerdictView::NotAffected {
            self.push_next_action(&mut lines, &findings);
        }

        let affected: Vec<String> = report
            .affected_member_names()
            .into_iter()
            .map(single_line)
            .collect();
        let affected_list = if affected.is_empty() {
            msgs.workspace_aggregate_none.to_string()
        } else {
            affected.join(", ")
        };
        lines.push(Messages::format(
            msgs.incident_workspace_aggregate,
            &[
                &affected.len().to_string(),
                &report.members.len().to_string(),
                &affected_list,
            ],
        ));
        finish(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        assert_no_english_labels, manual_report, position, report, verified,
    };
    use super::*;
    use crate::application::read_models::incident_report::{
        IncidentFinding, IncidentGuidance, IncidentSource, MemberIncidentResult,
    };
    use crate::i18n::Locale;

    fn workspace(members: Vec<(&str, Vec<IncidentFinding>)>) -> WorkspaceIncidentReport {
        let members: Vec<MemberIncidentResult> = members
            .into_iter()
            .map(|(name, findings)| {
                let overall = report(findings.clone()).overall;
                MemberIncidentResult {
                    name: name.to_string(),
                    findings,
                    overall,
                }
            })
            .collect();
        let overall = members
            .iter()
            .map(|m| m.overall)
            .find(|v| *v != IncidentVerdictView::NotAffected)
            .unwrap_or(IncidentVerdictView::NotAffected);
        let base = report(vec![]);
        WorkspaceIncidentReport {
            advisory_id: base.advisory_id,
            source: base.source,
            resolved_from: base.resolved_from,
            aliases: base.aliases,
            severity: base.severity,
            summary: base.summary,
            affected_packages: base.affected_packages,
            members,
            overall,
        }
    }

    fn transitive_from(root: &str) -> IncidentFinding {
        IncidentFinding {
            is_direct: false,
            paths: vec![vec![root.to_string(), "requests".to_string()]],
            ..verified()
        }
    }

    #[test]
    fn test_workspace_layout_en() {
        let out = IncidentMarkdownFormatter::new(Locale::En).format_workspace(&workspace(vec![
            ("api", vec![transitive_from("httpx")]),
            ("worker", vec![]),
        ]));

        let heading = position(&out, "## Incident Report: GHSA-j8r2-6x86-q33q");
        let impact = position(&out, "### 1. Impact");
        let api = position(&out, "#### Member: api");
        let worker = position(&out, "#### Member: worker");
        let patch = position(&out, "### 2. Patch status");
        let next = position(&out, "### 3. Next action");
        let aggregate = position(&out, "**1 of 2 members affected**: api");
        assert!(heading < impact && impact < api && api < worker && worker < patch);
        assert!(patch < next && next < aggregate);
        assert!(out.contains("- **Overall verdict**: Affected — fix released"));
        assert!(out.contains("- **Verdict**: Affected — fix released"));
        assert!(out.contains("    - `httpx → requests`"));
        assert!(out.contains("- **Verdict**: Not affected"));
        assert!(out
            .contains("None of the affected packages (requests) are reachable from this member."));
        assert!(out.ends_with("**1 of 2 members affected**: api\n"));
    }

    #[test]
    fn test_workspace_patch_status_and_command_rendered_once() {
        let out = IncidentMarkdownFormatter::new(Locale::En).format_workspace(&workspace(vec![
            ("api", vec![transitive_from("httpx")]),
            ("worker", vec![transitive_from("celery")]),
        ]));

        assert_eq!(out.matches("- **requests**: fixed in 2.31.0").count(), 1);
        assert_eq!(
            out.matches("uv lock --upgrade-package requests==2.31.0")
                .count(),
            1
        );
        assert!(out.contains("**2 of 2 members affected**: api, worker"));
    }

    #[test]
    fn test_workspace_direct_pin_wins_over_resolution_blocked() {
        let pinned = IncidentFinding {
            upgrade_command: None,
            command_verified: false,
            guidance: Some(IncidentGuidance::DirectPinBlocksUpgrade),
            ..verified()
        };
        let blocked = IncidentFinding {
            upgrade_command: None,
            command_verified: false,
            guidance: Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["httpx".to_string()],
            }),
            ..transitive_from("httpx")
        };
        let out = IncidentMarkdownFormatter::new(Locale::En).format_workspace(&workspace(vec![
            ("api", vec![blocked]),
            ("worker", vec![pinned]),
        ]));

        assert_eq!(
            out.matches("Relax the requirement to allow `>=2.31.0`")
                .count(),
            1
        );
        assert!(!out.contains("--suggest-fix"));
    }

    #[test]
    fn test_workspace_not_affected_omits_next_action() {
        let out = IncidentMarkdownFormatter::new(Locale::En)
            .format_workspace(&workspace(vec![("api", vec![]), ("worker", vec![])]));

        assert!(!out.contains("### 3. Next action"));
        assert!(out.contains("Not applicable — no workspace member is affected."));
        assert!(out.ends_with("**0 of 2 members affected**: none\n"));
    }

    #[test]
    fn test_workspace_ja_fully_localized() {
        let out = IncidentMarkdownFormatter::new(Locale::Ja).format_workspace(&workspace(vec![
            ("api", vec![transitive_from("httpx")]),
            ("worker", vec![]),
        ]));

        assert!(out.contains("#### メンバー: api"));
        assert!(out.contains("- **判定**: 影響あり — 修正版リリース済み"));
        assert!(out.contains("影響対象パッケージ（requests）はこのメンバーから到達しません。"));
        assert!(out.contains("**1 / 2 メンバーが影響あり**: api"));
        assert_no_english_labels(&out);
        for label in ["Member", "Verdict", "members affected", "reachable"] {
            assert!(!out.contains(label), "JA output contains {label:?}:\n{out}");
        }
    }

    #[test]
    fn test_workspace_manual_source_heading_and_notice() {
        let base = manual_report(vec![]);
        let report = WorkspaceIncidentReport {
            advisory_id: base.advisory_id,
            source: IncidentSource::Manual,
            resolved_from: None,
            aliases: vec![],
            severity: None,
            summary: None,
            ..workspace(vec![("api", vec![transitive_from("httpx")])])
        };

        let out = IncidentMarkdownFormatter::new(Locale::En).format_workspace(&report);

        assert!(out.starts_with("## Incident Report (manual range): `requests<2.31.0`\n"));
        assert!(out.contains("⚠️ This affected range was supplied by you."));
        assert!(!out.contains("**Aliases**"));
        assert!(out.contains("#### Member: api"));
    }
}
