// Dead in the bin target until wired to CLI in a subsequent subtask of #224.
// #[expect(dead_code)] cannot be used: the lib target does not see this as dead code
// (pub items are reachable by library consumers), making the expectation unfulfilled there.
#![allow(dead_code)]

use serde::Serialize;

use crate::sbom_generation::domain::dependency_diff::{ChangeType, DependencyDiff};
use crate::shared::Result;

/// Formats a `DependencyDiff` as machine-readable JSON.
///
/// Output shape:
/// ```json
/// { "diff": { "base": "<ref>", "summary": {...}, "changes": [...] } }
/// ```
/// Version fields are omitted when not applicable (e.g. `old_version` for Added packages).
pub struct DiffJsonFormatter;

impl DiffJsonFormatter {
    /// Creates a new `DiffJsonFormatter`.
    pub fn new() -> Self {
        Self
    }

    /// Serializes `diff` to a pretty-printed JSON string.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails (in practice this cannot happen
    /// because all field types are serializable).
    pub fn format(&self, diff: &DependencyDiff) -> Result<String> {
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

#[derive(Serialize)]
struct DiffEnvelope<'a> {
    diff: DiffBody<'a>,
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

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_top_level_shape_and_base_ref() {
        let diff = make_diff(vec![]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();

        assert!(json["diff"].is_object());
        assert_eq!(json["diff"]["base"], "main");
        assert!(json["diff"]["summary"].is_object());
        assert!(json["diff"]["changes"].is_array());
    }

    #[test]
    fn test_empty_diff() {
        let diff = make_diff(vec![]);
        let formatter = DiffJsonFormatter::new();
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();

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
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();
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
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();
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
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();
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
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();
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
        let json_str = formatter.format(&diff).unwrap();
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
        let json: Value = serde_json::from_str(&formatter.format(&diff).unwrap()).unwrap();

        assert_eq!(json["diff"]["summary"]["added"], 1);
        assert_eq!(json["diff"]["summary"]["removed"], 1);
        assert_eq!(json["diff"]["summary"]["updated"], 1);
        assert_eq!(json["diff"]["summary"]["unchanged"], 1);
        assert_eq!(json["diff"]["changes"].as_array().unwrap().len(), 4);
    }
}
