use serde::Serialize;

use crate::application::read_models::cve_delta_view::{CveDeltaEntry, CveDeltaView};
use crate::application::read_models::vulnerability_view::SeverityView;
use crate::sbom_generation::domain::dependency_diff::{ChangeType, DependencyDiff};
use crate::shared::Result;

/// Formats a `DependencyDiff` as machine-readable JSON.
///
/// Output shape:
/// ```json
/// { "diff": { "base": "<ref>", "summary": {...}, "changes": [...] } }
/// ```
/// When `cve_delta` is `Some`, a top-level `"cve_delta"` key is added alongside `"diff"`.
/// Version fields are omitted when not applicable (e.g. `old_version` for Added packages).
pub struct DiffJsonFormatter;

impl DiffJsonFormatter {
    /// Creates a new `DiffJsonFormatter`.
    pub fn new() -> Self {
        Self
    }

    /// Serializes `diff` to a pretty-printed JSON string.
    ///
    /// When `cve_delta` is `Some`, includes a top-level `"cve_delta"` object with `"new"` and
    /// `"resolved"` arrays. When `None`, the key is omitted entirely (backward-compatible output).
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails (in practice this cannot happen
    /// because all field types are serializable).
    pub fn format(
        &self,
        diff: &DependencyDiff,
        cve_delta: Option<&CveDeltaView>,
    ) -> Result<String> {
        let changes: Vec<ChangeDto> = diff
            .changes
            .iter()
            .map(|c| {
                let (old_version, new_version) = match c.change_type {
                    ChangeType::Added => (None, c.new_version.as_deref()),
                    ChangeType::Removed => (c.old_version.as_deref(), None),
                    ChangeType::Updated | ChangeType::Unchanged => {
                        (c.old_version.as_deref(), c.new_version.as_deref())
                    }
                };
                ChangeDto {
                    package: &c.package_name,
                    change: change_label(&c.change_type),
                    old_version,
                    new_version,
                    license: c.license.as_deref(),
                }
            })
            .collect();

        let cve_delta_dto = cve_delta.map(map_cve_delta);

        let envelope = DiffEnvelope {
            diff: DiffBody {
                base: &diff.base_ref,
                summary: SummaryDto {
                    added: diff.summary.added,
                    removed: diff.summary.removed,
                    updated: diff.summary.updated,
                    unchanged: diff.summary.unchanged,
                },
                changes,
            },
            cve_delta: cve_delta_dto,
        };

        serde_json::to_string_pretty(&envelope).map_err(Into::into)
    }
}

impl Default for DiffJsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

fn change_label(change_type: &ChangeType) -> &'static str {
    match change_type {
        ChangeType::Added => "added",
        ChangeType::Removed => "removed",
        ChangeType::Updated => "updated",
        ChangeType::Unchanged => "unchanged",
    }
}

fn map_cve_delta(delta: &CveDeltaView) -> CveDeltaDto<'_> {
    CveDeltaDto {
        new: delta.new.iter().map(map_cve_entry).collect(),
        resolved: delta.resolved.iter().map(map_cve_entry).collect(),
    }
}

fn map_cve_entry(entry: &CveDeltaEntry) -> CveDeltaEntryDto<'_> {
    CveDeltaEntryDto {
        package: &entry.package_name,
        version: &entry.version,
        cve_id: &entry.cve_id,
        severity: entry.severity.as_ref().map(SeverityView::as_str),
        summary: &entry.summary,
    }
}

#[derive(Serialize)]
struct DiffEnvelope<'a> {
    diff: DiffBody<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve_delta: Option<CveDeltaDto<'a>>,
}

#[derive(Serialize)]
struct DiffBody<'a> {
    base: &'a str,
    summary: SummaryDto,
    changes: Vec<ChangeDto<'a>>,
}

#[derive(Serialize)]
struct SummaryDto {
    added: usize,
    removed: usize,
    updated: usize,
    unchanged: usize,
}

#[derive(Serialize)]
struct ChangeDto<'a> {
    package: &'a str,
    change: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<&'a str>,
}

#[derive(Serialize)]
struct CveDeltaDto<'a> {
    new: Vec<CveDeltaEntryDto<'a>>,
    resolved: Vec<CveDeltaEntryDto<'a>>,
}

#[derive(Serialize)]
struct CveDeltaEntryDto<'a> {
    package: &'a str,
    version: &'a str,
    cve_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<&'static str>,
    summary: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::cve_delta_view::{CveDeltaEntry, CveDeltaView};
    use crate::application::read_models::vulnerability_view::SeverityView;
    use crate::sbom_generation::domain::dependency_diff::{
        ChangeType, DependencyDiff, DiffSummary, PackageChange,
    };
    use serde_json::Value;

    fn make_diff(changes: Vec<PackageChange>) -> DependencyDiff {
        let summary = DiffSummary {
            added: changes
                .iter()
                .filter(|c| c.change_type == ChangeType::Added)
                .count(),
            removed: changes
                .iter()
                .filter(|c| c.change_type == ChangeType::Removed)
                .count(),
            updated: changes
                .iter()
                .filter(|c| c.change_type == ChangeType::Updated)
                .count(),
            unchanged: changes
                .iter()
                .filter(|c| c.change_type == ChangeType::Unchanged)
                .count(),
        };
        DependencyDiff {
            base_ref: "main".to_string(),
            changes,
            summary,
        }
    }

    fn make_change(
        name: &str,
        change_type: ChangeType,
        old: Option<&str>,
        new: Option<&str>,
        license: Option<&str>,
        vuln_count: usize,
    ) -> PackageChange {
        PackageChange {
            package_name: name.to_string(),
            change_type,
            old_version: old.map(str::to_string),
            new_version: new.map(str::to_string),
            license: license.map(str::to_string),
            vulnerability_count: vuln_count,
        }
    }

    fn make_entry(
        package: &str,
        version: &str,
        cve_id: &str,
        severity: Option<SeverityView>,
        summary: &str,
    ) -> CveDeltaEntry {
        CveDeltaEntry::new(
            package.to_string(),
            version.to_string(),
            cve_id.to_string(),
            severity,
            summary.to_string(),
        )
    }

    #[test]
    fn test_top_level_shape_and_base_ref() {
        let diff = make_diff(vec![]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();

        assert!(json["diff"].is_object());
        assert_eq!(json["diff"]["base"], "main");
        assert!(json["diff"]["summary"].is_object());
        assert!(json["diff"]["changes"].is_array());
    }

    #[test]
    fn test_empty_diff() {
        let diff = make_diff(vec![]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();

        assert_eq!(json["diff"]["summary"]["added"], 0);
        assert_eq!(json["diff"]["summary"]["removed"], 0);
        assert_eq!(json["diff"]["summary"]["updated"], 0);
        assert_eq!(json["diff"]["summary"]["unchanged"], 0);
        assert_eq!(json["diff"]["changes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_added_omits_old_version() {
        let diff = make_diff(vec![make_change(
            "pydantic",
            ChangeType::Added,
            None,
            Some("2.9.0"),
            Some("MIT"),
            0,
        )]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();
        let change = &json["diff"]["changes"][0];

        assert_eq!(change["change"], "added");
        assert_eq!(change["new_version"], "2.9.0");
        assert!(change["old_version"].is_null());
        assert_eq!(change["license"], "MIT");
    }

    #[test]
    fn test_removed_omits_new_version() {
        let diff = make_diff(vec![make_change(
            "flask",
            ChangeType::Removed,
            Some("3.0.0"),
            None,
            Some("BSD-3-Clause"),
            0,
        )]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();
        let change = &json["diff"]["changes"][0];

        assert_eq!(change["change"], "removed");
        assert_eq!(change["old_version"], "3.0.0");
        assert!(change["new_version"].is_null());
    }

    #[test]
    fn test_updated_keeps_both_versions() {
        let diff = make_diff(vec![make_change(
            "requests",
            ChangeType::Updated,
            Some("2.31.0"),
            Some("2.32.0"),
            Some("Apache-2.0"),
            0,
        )]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();
        let change = &json["diff"]["changes"][0];

        assert_eq!(change["change"], "updated");
        assert_eq!(change["old_version"], "2.31.0");
        assert_eq!(change["new_version"], "2.32.0");
    }

    #[test]
    fn test_unchanged_keeps_both_versions() {
        let diff = make_diff(vec![make_change(
            "urllib3",
            ChangeType::Unchanged,
            Some("1.26.0"),
            Some("1.26.0"),
            None,
            0,
        )]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();
        let change = &json["diff"]["changes"][0];

        assert_eq!(change["change"], "unchanged");
        assert_eq!(change["old_version"], "1.26.0");
        assert_eq!(change["new_version"], "1.26.0");
    }

    #[test]
    fn test_missing_license_omits_field() {
        let diff = make_diff(vec![make_change(
            "somelib",
            ChangeType::Added,
            None,
            Some("1.0.0"),
            None,
            0,
        )]);
        let formatter = DiffJsonFormatter::new();
        let json_str = formatter.format(&diff, None).unwrap();
        let json: Value = serde_json::from_str(&json_str).unwrap();

        assert!(json["diff"]["changes"][0]["license"].is_null());
        assert!(!json_str.contains("\"license\""));
    }

    #[test]
    fn test_all_change_types_in_one_diff() {
        let diff = make_diff(vec![
            make_change("a", ChangeType::Added, None, Some("1.0.0"), Some("MIT"), 0),
            make_change(
                "b",
                ChangeType::Removed,
                Some("0.5.0"),
                None,
                Some("Apache-2.0"),
                0,
            ),
            make_change(
                "c",
                ChangeType::Updated,
                Some("2.0.0"),
                Some("2.1.0"),
                None,
                1,
            ),
            make_change(
                "d",
                ChangeType::Unchanged,
                Some("3.0.0"),
                Some("3.0.0"),
                None,
                0,
            ),
        ]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff, None).unwrap()).unwrap();

        assert_eq!(json["diff"]["summary"]["added"], 1);
        assert_eq!(json["diff"]["summary"]["removed"], 1);
        assert_eq!(json["diff"]["summary"]["updated"], 1);
        assert_eq!(json["diff"]["summary"]["unchanged"], 1);
        assert_eq!(json["diff"]["changes"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_cve_delta_key_absent_when_none() {
        let diff = make_diff(vec![]);
        let json_str = DiffJsonFormatter::new().format(&diff, None).unwrap();
        let json: Value = serde_json::from_str(&json_str).unwrap();

        assert!(json["cve_delta"].is_null());
        assert!(!json_str.contains("\"cve_delta\""));
    }

    #[test]
    fn test_cve_delta_key_present_with_empty_lists() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView::default();
        let json: Value = serde_json::from_str(
            &DiffJsonFormatter::new()
                .format(&diff, Some(&delta))
                .unwrap(),
        )
        .unwrap();

        assert!(json["cve_delta"].is_object());
        assert_eq!(json["cve_delta"]["new"].as_array().unwrap().len(), 0);
        assert_eq!(json["cve_delta"]["resolved"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_cve_delta_new_entry_serialized() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![make_entry(
                "cryptography",
                "41.0.0",
                "CVE-2024-0727",
                Some(SeverityView::High),
                "Null pointer dereference",
            )],
            resolved: vec![],
        };
        let json: Value = serde_json::from_str(
            &DiffJsonFormatter::new()
                .format(&diff, Some(&delta))
                .unwrap(),
        )
        .unwrap();
        let entry = &json["cve_delta"]["new"][0];

        assert_eq!(entry["package"], "cryptography");
        assert_eq!(entry["version"], "41.0.0");
        assert_eq!(entry["cve_id"], "CVE-2024-0727");
        assert_eq!(entry["severity"], "HIGH");
        assert_eq!(entry["summary"], "Null pointer dereference");
    }

    #[test]
    fn test_cve_delta_resolved_entry_serialized() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![],
            resolved: vec![make_entry(
                "requests",
                "2.28.0",
                "CVE-2023-32681",
                Some(SeverityView::Medium),
                "Fixed in 2.31.0",
            )],
        };
        let json: Value = serde_json::from_str(
            &DiffJsonFormatter::new()
                .format(&diff, Some(&delta))
                .unwrap(),
        )
        .unwrap();
        let entry = &json["cve_delta"]["resolved"][0];

        assert_eq!(entry["package"], "requests");
        assert_eq!(entry["cve_id"], "CVE-2023-32681");
        assert_eq!(entry["severity"], "MEDIUM");
    }

    #[test]
    fn test_cve_delta_severity_omitted_when_option_none() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![make_entry("pkg", "1.0.0", "CVE-2024-0001", None, "desc")],
            resolved: vec![],
        };
        let json_str = DiffJsonFormatter::new()
            .format(&diff, Some(&delta))
            .unwrap();
        let json: Value = serde_json::from_str(&json_str).unwrap();

        assert!(json["cve_delta"]["new"][0]["severity"].is_null());
        // severity key itself is omitted when None
        assert!(!json_str.lines().any(|l| l.contains("\"severity\"")
            && !l.contains("HIGH")
            && !l.contains("MEDIUM")
            && !l.contains("LOW")
            && !l.contains("CRITICAL")
            && !l.contains("NONE")));
    }

    #[test]
    fn test_cve_delta_severity_none_variant_renders_as_none_string() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![make_entry(
                "pkg",
                "1.0.0",
                "CVE-2024-0002",
                Some(SeverityView::None),
                "desc",
            )],
            resolved: vec![],
        };
        let json: Value = serde_json::from_str(
            &DiffJsonFormatter::new()
                .format(&diff, Some(&delta))
                .unwrap(),
        )
        .unwrap();

        assert_eq!(json["cve_delta"]["new"][0]["severity"], "NONE");
    }
}
