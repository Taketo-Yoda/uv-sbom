use std::fmt::Write;

use crate::application::read_models::cve_delta_view::{CveDeltaEntry, CveDeltaView};
use crate::application::read_models::vulnerability_view::SeverityView;
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
    ///
    /// When `cve_delta` is `Some`, a `## CVE Delta` section is appended with tables
    /// for newly introduced and resolved vulnerabilities. When `None`, the section
    /// is omitted entirely (e.g., when `--no-check-cve` was passed).
    pub fn format(&self, diff: &DependencyDiff, cve_delta: Option<&CveDeltaView>) -> String {
        let mut out = String::new();

        writeln!(out, "## Dependency Diff Report").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "Compared: `{}` vs current `uv.lock`", diff.base_ref).unwrap();
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

        if let Some(delta) = cve_delta {
            writeln!(out).unwrap();
            writeln!(out, "## CVE Delta").unwrap();
            writeln!(out).unwrap();

            writeln!(out, "### 🔴 New Vulnerabilities ({})", delta.new.len()).unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Package | Version | CVE | Severity | Summary |").unwrap();
            writeln!(out, "|---------|---------|-----|----------|---------|").unwrap();
            if delta.new.is_empty() {
                writeln!(out, "| — | — | — | — | No new vulnerabilities |").unwrap();
            } else {
                for entry in &delta.new {
                    writeln!(out, "{}", format_cve_row(entry)).unwrap();
                }
            }

            writeln!(out).unwrap();

            writeln!(
                out,
                "### ✅ Resolved Vulnerabilities ({})",
                delta.resolved.len()
            )
            .unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Package | Version | CVE | Severity | Summary |").unwrap();
            writeln!(out, "|---------|---------|-----|----------|---------|").unwrap();
            if delta.resolved.is_empty() {
                writeln!(out, "| — | — | — | — | No resolved vulnerabilities |").unwrap();
            } else {
                for entry in &delta.resolved {
                    writeln!(out, "{}", format_cve_row(entry)).unwrap();
                }
            }
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

/// Formats a single `CveDeltaEntry` as a Markdown table row.
///
/// Column order: `Package | Version | CVE | Severity | Summary`.
/// `Option::None` severity renders as `"UNKNOWN"`; `Some(SeverityView::None)` renders as `"NONE"`.
/// Literal `|` characters in `summary` are escaped as `\|` to avoid breaking the table.
fn format_cve_row(entry: &CveDeltaEntry) -> String {
    let severity = entry
        .severity
        .as_ref()
        .map(SeverityView::as_str)
        .unwrap_or("UNKNOWN");
    let summary = entry.summary.replace('|', "\\|");
    format!(
        "| {} | {} | {} | {} | {} |",
        entry.package_name, entry.version, entry.cve_id, severity, summary
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
    use crate::application::read_models::cve_delta_view::{CveDeltaEntry, CveDeltaView};
    use crate::application::read_models::vulnerability_view::SeverityView;
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
    fn test_header_and_compared_line() {
        let diff = make_diff(vec![]);
        let formatter = DiffMarkdownFormatter::new();
        let md = formatter.format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

        assert!(md.contains("| Added | 2 |"));
        assert!(md.contains("| Removed | 1 |"));
        assert!(md.contains("| Updated | 3 |"));
        assert!(md.contains("| Unchanged | 45 |"));
    }

    #[test]
    fn test_changes_table_header_always_present() {
        let diff = make_diff(vec![]);
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);

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
        let md = DiffMarkdownFormatter::new().format(&diff, None);
        let summary_pos = md.find("### Summary").unwrap();
        let changes_pos = md.find("### Changes").unwrap();
        assert!(summary_pos < changes_pos);
    }

    #[test]
    fn test_cve_delta_section_absent_when_none() {
        let diff = make_diff(vec![]);
        let md = DiffMarkdownFormatter::new().format(&diff, None);

        assert!(!md.contains("## CVE Delta"));
    }

    #[test]
    fn test_cve_delta_section_present_with_empty_lists() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView::default();
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("## CVE Delta"));
        assert!(md.contains("### 🔴 New Vulnerabilities (0)"));
        assert!(md.contains("### ✅ Resolved Vulnerabilities (0)"));
        assert!(md.contains("No new vulnerabilities"));
        assert!(md.contains("No resolved vulnerabilities"));
    }

    #[test]
    fn test_cve_delta_new_row_renders_with_severity() {
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
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("### 🔴 New Vulnerabilities (1)"));
        assert!(md.contains(
            "| cryptography | 41.0.0 | CVE-2024-0727 | HIGH | Null pointer dereference |"
        ));
    }

    #[test]
    fn test_cve_delta_resolved_row_renders() {
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
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("### ✅ Resolved Vulnerabilities (1)"));
        assert!(md.contains("| requests | 2.28.0 | CVE-2023-32681 | MEDIUM | Fixed in 2.31.0 |"));
    }

    #[test]
    fn test_cve_delta_unknown_severity_when_option_none() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![make_entry("pkg", "1.0.0", "CVE-2024-0001", None, "desc")],
            resolved: vec![],
        };
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("| pkg | 1.0.0 | CVE-2024-0001 | UNKNOWN | desc |"));
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
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("| pkg | 1.0.0 | CVE-2024-0002 | NONE | desc |"));
    }

    #[test]
    fn test_cve_delta_pipe_in_summary_is_escaped() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView {
            new: vec![make_entry(
                "pkg",
                "1.0.0",
                "CVE-2024-0003",
                Some(SeverityView::Low),
                "see CVE | NVD",
            )],
            resolved: vec![],
        };
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        assert!(md.contains("see CVE \\| NVD"));
    }

    #[test]
    fn test_cve_delta_section_after_changes_section() {
        let diff = make_diff(vec![]);
        let delta = CveDeltaView::default();
        let md = DiffMarkdownFormatter::new().format(&diff, Some(&delta));

        let changes_pos = md.find("### Changes").unwrap();
        let cve_pos = md.find("## CVE Delta").unwrap();
        assert!(changes_pos < cve_pos);
    }
}
