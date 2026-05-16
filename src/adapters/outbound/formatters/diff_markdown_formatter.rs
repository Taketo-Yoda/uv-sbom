// Dead in the bin target until wired to CLI in a subsequent subtask of #224.
// #[expect(dead_code)] cannot be used: the lib target does not see this as dead code
// (pub items are reachable by library consumers), making the expectation unfulfilled there.
#![allow(dead_code)]

use std::fmt::Write;

use crate::sbom_generation::domain::dependency_diff::{ChangeType, DependencyDiff, PackageChange};

/// Formats a `DependencyDiff` as a human-readable Markdown report.
///
/// Produces a two-section report: a summary table with aggregate counts, and a
/// changes table listing every package with its change type, versions, license,
/// and vulnerability count.
pub struct DiffMarkdownFormatter;

impl DiffMarkdownFormatter {
    /// Creates a new `DiffMarkdownFormatter`.
    pub fn new() -> Self {
        Self
    }

    /// Formats `diff` as a Markdown string. This operation is infallible.
    pub fn format(&self, diff: &DependencyDiff) -> String {
        let mut out = String::new();

        writeln!(out, "## Dependency Diff Report").unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "Compared: `{}` vs current `uv.lock`",
            diff.base_ref
        )
        .unwrap();
        writeln!(out).unwrap();

        writeln!(out, "### Summary").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Metric | Count |").unwrap();
        writeln!(out, "|--------|-------|").unwrap();
        writeln!(out, "| Added | {} |", diff.summary.added).unwrap();
        writeln!(out, "| Removed | {} |", diff.summary.removed).unwrap();
        writeln!(out, "| Updated | {} |", diff.summary.updated).unwrap();
        writeln!(out, "| Unchanged | {} |", diff.summary.unchanged).unwrap();
        writeln!(out).unwrap();

        writeln!(out, "### Changes").unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "| Package | Change | Old Version | New Version | License | Vulnerabilities |"
        )
        .unwrap();
        writeln!(
            out,
            "|---------|--------|-------------|-------------|---------|-----------------|"
        )
        .unwrap();

        for change in &diff.changes {
            writeln!(out, "{}", format_change_row(change)).unwrap();
        }

        out
    }
}

impl Default for DiffMarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

fn format_change_row(change: &PackageChange) -> String {
    let change_label = match change.change_type {
        ChangeType::Added => "Added",
        ChangeType::Removed => "Removed",
        ChangeType::Updated => "Updated",
        ChangeType::Unchanged => "Unchanged",
    };
    let old = version_cell(&change.old_version);
    let new = version_cell(&change.new_version);
    let license = version_cell(&change.license);
    let vulns = vuln_cell(&change.change_type, change.vulnerability_count);
    format!(
        "| {} | {} | {} | {} | {} | {} |",
        change.package_name, change_label, old, new, license, vulns
    )
}

fn version_cell(opt: &Option<String>) -> &str {
    opt.as_deref().unwrap_or("-")
}

fn vuln_cell(change_type: &ChangeType, count: usize) -> String {
    if matches!(change_type, ChangeType::Removed) {
        return "-".to_string();
    }
    if count == 0 {
        "None".to_string()
    } else {
        count.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::dependency_diff::{
        ChangeType, DependencyDiff, DiffSummary, PackageChange,
    };

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
    fn test_header_and_compared_line() {
        let diff = make_diff(vec![]);
        let formatter = DiffMarkdownFormatter::new();
        let md = formatter.format(&diff);

        assert!(md.contains("## Dependency Diff Report"));
        assert!(md.contains("Compared: `main` vs current `uv.lock`"));
    }

    #[test]
    fn test_summary_table_rows() {
        let diff = DependencyDiff {
            base_ref: "main".to_string(),
            changes: vec![],
            summary: DiffSummary {
                added: 2,
                removed: 1,
                updated: 3,
                unchanged: 45,
            },
        };
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| Added | 2 |"));
        assert!(md.contains("| Removed | 1 |"));
        assert!(md.contains("| Updated | 3 |"));
        assert!(md.contains("| Unchanged | 45 |"));
    }

    #[test]
    fn test_changes_table_header_always_present() {
        let diff = make_diff(vec![]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains(
            "| Package | Change | Old Version | New Version | License | Vulnerabilities |"
        ));
        assert!(md.contains(
            "|---------|--------|-------------|-------------|---------|-----------------|"
        ));
    }

    #[test]
    fn test_added_package_row() {
        let diff = make_diff(vec![make_change(
            "pydantic",
            ChangeType::Added,
            None,
            Some("2.9.0"),
            Some("MIT"),
            0,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| pydantic | Added | - | 2.9.0 | MIT | None |"));
    }

    #[test]
    fn test_removed_package_row() {
        let diff = make_diff(vec![make_change(
            "flask",
            ChangeType::Removed,
            Some("3.0.0"),
            None,
            Some("BSD-3-Clause"),
            0,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| flask | Removed | 3.0.0 | - | BSD-3-Clause | - |"));
    }

    #[test]
    fn test_updated_package_row() {
        let diff = make_diff(vec![make_change(
            "requests",
            ChangeType::Updated,
            Some("2.31.0"),
            Some("2.32.0"),
            Some("Apache-2.0"),
            0,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| requests | Updated | 2.31.0 | 2.32.0 | Apache-2.0 | None |"));
    }

    #[test]
    fn test_unchanged_package_row() {
        let diff = make_diff(vec![make_change(
            "urllib3",
            ChangeType::Unchanged,
            Some("1.26.0"),
            Some("1.26.0"),
            Some("MIT"),
            0,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| urllib3 | Unchanged | 1.26.0 | 1.26.0 | MIT | None |"));
    }

    #[test]
    fn test_vuln_cell_shows_count_when_nonzero() {
        let diff = make_diff(vec![make_change(
            "vuln-pkg",
            ChangeType::Updated,
            Some("1.0.0"),
            Some("1.1.0"),
            None,
            3,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| vuln-pkg | Updated | 1.0.0 | 1.1.0 | - | 3 |"));
    }

    #[test]
    fn test_vuln_cell_dash_for_removed_regardless_of_count() {
        let diff = make_diff(vec![make_change(
            "gone",
            ChangeType::Removed,
            Some("1.0.0"),
            None,
            None,
            5,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| gone | Removed | 1.0.0 | - | - | - |"));
    }

    #[test]
    fn test_missing_license_shows_dash() {
        let diff = make_diff(vec![make_change(
            "nolic",
            ChangeType::Added,
            None,
            Some("0.1.0"),
            None,
            0,
        )]);
        let md = DiffMarkdownFormatter::new().format(&diff);

        assert!(md.contains("| nolic | Added | - | 0.1.0 | - | None |"));
    }

    #[test]
    fn test_section_order() {
        let diff = DependencyDiff {
            base_ref: "main".to_string(),
            changes: vec![],
            summary: DiffSummary {
                added: 0,
                removed: 0,
                updated: 0,
                unchanged: 0,
            },
        };
        let md = DiffMarkdownFormatter::new().format(&diff);
        let summary_pos = md.find("### Summary").unwrap();
        let changes_pos = md.find("### Changes").unwrap();
        assert!(summary_pos < changes_pos);
    }
}
