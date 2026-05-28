//! CVE delta view model for read-side queries
//!
//! Captures the difference in CVE exposure between two SBOM snapshots:
//! which CVEs are newly introduced and which have been resolved.

use super::vulnerability_view::SeverityView;

/// Container describing the change in CVE exposure between two SBOM snapshots.
#[derive(Debug, Clone, Default)]
pub struct CveDeltaView {
    /// Newly introduced CVEs (present in the newer snapshot, absent from the baseline).
    pub new: Vec<CveDeltaEntry>,
    /// Resolved CVEs (present in the baseline, absent from the newer snapshot).
    pub resolved: Vec<CveDeltaEntry>,
}

/// Single CVE change entry for a specific package/version.
#[derive(Debug, Clone)]
pub struct CveDeltaEntry {
    /// Name of the affected package.
    pub package_name: String,
    /// Version of the affected package.
    pub version: String,
    /// CVE identifier (e.g., "CVE-2024-1234").
    pub cve_id: String,
    /// Severity level. `None` means the CVE has not yet been scored;
    /// `Some(SeverityView::None)` means it was explicitly scored as no severity.
    pub severity: Option<SeverityView>,
    /// Short description of the vulnerability.
    pub summary: String,
}

impl CveDeltaEntry {
    /// Creates a new [`CveDeltaEntry`].
    pub fn new(
        package_name: String,
        version: String,
        cve_id: String,
        severity: Option<SeverityView>,
        summary: String,
    ) -> Self {
        CveDeltaEntry {
            package_name,
            version,
            cve_id,
            severity,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(cve: &str, severity: Option<SeverityView>) -> CveDeltaEntry {
        CveDeltaEntry::new(
            "requests".to_string(),
            "2.28.0".to_string(),
            cve.to_string(),
            severity,
            "Test summary".to_string(),
        )
    }

    #[test]
    fn test_cve_delta_entry_new_all_fields_are_stored() {
        let entry = make_entry("CVE-2024-1234", Some(SeverityView::High));
        assert_eq!(entry.package_name, "requests");
        assert_eq!(entry.version, "2.28.0");
        assert_eq!(entry.cve_id, "CVE-2024-1234");
        assert_eq!(entry.severity, Some(SeverityView::High));
        assert_eq!(entry.summary, "Test summary");
    }

    #[test]
    fn test_cve_delta_entry_severity_some_as_str_returns_variant_name() {
        let entry = make_entry("CVE-2024-0001", Some(SeverityView::Critical));
        assert_eq!(entry.severity, Some(SeverityView::Critical));
        assert_eq!(entry.severity.unwrap().as_str(), "CRITICAL");
    }

    #[test]
    fn test_cve_delta_entry_severity_none_differs_from_explicit_none_variant() {
        let unscored = make_entry("CVE-2024-0002", None);
        let explicit_none = make_entry("CVE-2024-0002", Some(SeverityView::None));
        assert!(unscored.severity.is_none());
        assert!(explicit_none.severity.is_some());
        assert_ne!(unscored.severity, explicit_none.severity);
    }

    #[test]
    fn test_cve_delta_view_default_produces_empty_lists() {
        let view = CveDeltaView::default();
        assert!(view.new.is_empty());
        assert!(view.resolved.is_empty());
    }

    #[test]
    fn test_cve_delta_view_new_and_resolved_are_independent() {
        let view = CveDeltaView {
            new: vec![make_entry("CVE-2024-0001", Some(SeverityView::High))],
            resolved: vec![
                make_entry("CVE-2023-9999", Some(SeverityView::Medium)),
                make_entry("CVE-2023-8888", None),
            ],
        };
        assert_eq!(view.new.len(), 1);
        assert_eq!(view.resolved.len(), 2);
        assert_eq!(view.new[0].cve_id, "CVE-2024-0001");
        assert_eq!(view.resolved[0].cve_id, "CVE-2023-9999");
    }

    #[test]
    fn test_cve_delta_entry_clone_produces_equal_fields() {
        let original = make_entry("CVE-2024-0003", Some(SeverityView::Low));
        let cloned = original.clone();
        assert_eq!(cloned.package_name, original.package_name);
        assert_eq!(cloned.version, original.version);
        assert_eq!(cloned.cve_id, original.cve_id);
        assert_eq!(cloned.severity, original.severity);
        assert_eq!(cloned.summary, original.summary);
    }
}
