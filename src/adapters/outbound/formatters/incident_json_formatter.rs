use crate::application::read_models::incident_report::{IncidentReport, WorkspaceIncidentReport};
use crate::shared::Result;

/// Formats an `IncidentReport` as machine-readable JSON (#967).
///
/// The output is a direct, pretty-printed serde serialization of the read
/// model, so its keys are the read model's snake_case field names: report keys
/// `advisory_id`, `source` (`"osv"` or `"manual"`, #963), `resolved_from`,
/// `aliases`, `severity`, `summary`, `affected_packages`, `findings`,
/// `overall`. Absent options serialize as
/// `null` rather than being omitted, so the key set is stable.
pub struct IncidentJsonFormatter;

impl IncidentJsonFormatter {
    /// Creates a new `IncidentJsonFormatter`.
    pub fn new() -> Self {
        Self
    }

    /// Serializes `report` to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails (in practice this cannot
    /// happen because all field types are serializable).
    pub fn format(&self, report: &IncidentReport) -> Result<String> {
        serde_json::to_string_pretty(report).map_err(Into::into)
    }

    /// Serializes a workspace report (#969) to a pretty-printed JSON string:
    /// the advisory keys of `format`, then `members` (each with `name`,
    /// `findings`, `overall`) in place of `findings`, then the workspace
    /// `overall`.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails (in practice this cannot
    /// happen because all field types are serializable).
    pub fn format_workspace(&self, report: &WorkspaceIncidentReport) -> Result<String> {
        serde_json::to_string_pretty(report).map_err(Into::into)
    }
}

impl Default for IncidentJsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::incident_report::{
        IncidentFinding, IncidentGuidance, IncidentSource, IncidentVerdictView,
        MemberIncidentResult, ReleaseStatusView,
    };
    use crate::application::read_models::vulnerability_view::SeverityView;
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    fn report() -> IncidentReport {
        IncidentReport {
            advisory_id: "GHSA-j8r2-6x86-q33q".to_string(),
            source: IncidentSource::Osv,
            resolved_from: Some("CVE-2023-32681".to_string()),
            aliases: vec!["CVE-2023-32681".to_string()],
            severity: Some(SeverityView::Medium),
            summary: None,
            affected_packages: vec!["requests".to_string()],
            findings: vec![IncidentFinding {
                package_name: "requests".to_string(),
                locked_version: "2.25.0".to_string(),
                is_direct: false,
                paths: vec![vec!["flask".to_string(), "requests".to_string()]],
                fixed_version: Some("2.31.0".to_string()),
                release_status: Some(ReleaseStatusView::NotFound),
                verdict: IncidentVerdictView::AffectedFixUnreleased,
                upgrade_command: None,
                command_verified: false,
                guidance: Some(IncidentGuidance::NoReleasedFix),
            }],
            overall: IncidentVerdictView::AffectedFixUnreleased,
        }
    }

    fn keys(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    fn parsed() -> Value {
        serde_json::from_str(&IncidentJsonFormatter::new().format(&report()).unwrap()).unwrap()
    }

    #[test]
    fn test_report_key_set() {
        assert_eq!(
            keys(&parsed()),
            BTreeSet::from([
                "advisory_id",
                "source",
                "resolved_from",
                "aliases",
                "severity",
                "summary",
                "affected_packages",
                "findings",
                "overall",
            ])
        );
    }

    #[test]
    fn test_source_serializes_as_snake_case() {
        assert_eq!(parsed()["source"], json!("osv"));

        let manual = IncidentReport {
            advisory_id: "requests<2.31.0".to_string(),
            source: IncidentSource::Manual,
            ..report()
        };
        let value: Value =
            serde_json::from_str(&IncidentJsonFormatter::new().format(&manual).unwrap()).unwrap();
        assert_eq!(value["source"], json!("manual"));
        assert_eq!(value["advisory_id"], json!("requests<2.31.0"));
    }

    #[test]
    fn test_finding_key_set() {
        assert_eq!(
            keys(&parsed()["findings"][0]),
            BTreeSet::from([
                "package_name",
                "locked_version",
                "is_direct",
                "paths",
                "fixed_version",
                "release_status",
                "verdict",
                "upgrade_command",
                "command_verified",
                "guidance",
            ])
        );
    }

    #[test]
    fn test_values_are_snake_case_and_nulls_kept() {
        let json = parsed();

        assert_eq!(json["overall"], json!("affected_fix_unreleased"));
        assert_eq!(json["severity"], json!("MEDIUM"));
        assert_eq!(json["summary"], Value::Null);
        assert_eq!(json["resolved_from"], json!("CVE-2023-32681"));

        let finding = &json["findings"][0];
        assert_eq!(finding["verdict"], json!("affected_fix_unreleased"));
        assert_eq!(finding["release_status"], json!("not_found"));
        assert_eq!(finding["upgrade_command"], Value::Null);
        assert_eq!(finding["paths"], json!([["flask", "requests"]]));
        assert_eq!(finding["guidance"], json!({"kind": "no_released_fix"}));
    }

    #[test]
    fn test_direct_pin_and_resolution_blocked_guidance_tags_differ() {
        for (guidance, expected) in [
            (
                IncidentGuidance::DirectPinBlocksUpgrade,
                json!({"kind": "direct_pin_blocks_upgrade"}),
            ),
            (
                IncidentGuidance::ResolutionBlocked {
                    direct_roots: vec!["flask".to_string()],
                },
                json!({"kind": "resolution_blocked", "direct_roots": ["flask"]}),
            ),
        ] {
            let mut r = report();
            r.findings[0].guidance = Some(guidance);

            let json: Value =
                serde_json::from_str(&IncidentJsonFormatter::new().format(&r).unwrap()).unwrap();

            assert_eq!(json["findings"][0]["guidance"], expected);
        }
    }

    #[test]
    fn test_release_lookup_and_non_pypi_guidance_tags() {
        for (guidance, expected) in [
            (
                IncidentGuidance::ReleaseLookupFailed {
                    reason: "timeout".to_string(),
                },
                json!({"kind": "release_lookup_failed", "reason": "timeout"}),
            ),
            (
                IncidentGuidance::NotFromPyPi,
                json!({"kind": "not_from_pypi"}),
            ),
        ] {
            let mut r = report();
            r.findings[0].release_status = None;
            r.findings[0].guidance = Some(guidance);

            let json: Value =
                serde_json::from_str(&IncidentJsonFormatter::new().format(&r).unwrap()).unwrap();

            assert_eq!(json["findings"][0]["guidance"], expected);
            assert_eq!(json["findings"][0]["release_status"], Value::Null);
            assert_eq!(
                json["findings"][0]["verdict"],
                json!("affected_fix_unreleased")
            );
        }
    }

    #[test]
    fn test_workspace_report_keys_and_members() {
        let single = report();
        let workspace = WorkspaceIncidentReport {
            advisory_id: single.advisory_id,
            source: single.source,
            resolved_from: single.resolved_from,
            aliases: single.aliases,
            severity: single.severity,
            summary: single.summary,
            affected_packages: single.affected_packages,
            members: vec![
                MemberIncidentResult {
                    name: "api".to_string(),
                    findings: single.findings,
                    overall: IncidentVerdictView::AffectedFixUnreleased,
                },
                MemberIncidentResult {
                    name: "worker".to_string(),
                    findings: vec![],
                    overall: IncidentVerdictView::NotAffected,
                },
            ],
            overall: IncidentVerdictView::AffectedFixUnreleased,
        };

        let value: Value = serde_json::from_str(
            &IncidentJsonFormatter::new()
                .format_workspace(&workspace)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            keys(&value),
            BTreeSet::from([
                "advisory_id",
                "source",
                "resolved_from",
                "aliases",
                "severity",
                "summary",
                "affected_packages",
                "members",
                "overall",
            ])
        );
        assert_eq!(
            keys(&value["members"][0]),
            BTreeSet::from(["name", "findings", "overall"])
        );
        assert_eq!(value["members"][1]["name"], json!("worker"));
        assert_eq!(value["members"][1]["findings"], json!([]));
        assert_eq!(value["members"][1]["overall"], json!("not_affected"));
        assert_eq!(value["overall"], json!("affected_fix_unreleased"));
    }
}
