//! Resolution guide view structs for read model
//!
//! These structs provide a query-optimized view of the resolution guide,
//! showing which direct dependencies introduce vulnerable transitive packages.

use super::vulnerability_view::SeverityView;

/// View representation of the resolution guide section
///
/// Contains a list of resolution entries that map vulnerable transitive
/// dependencies back to the direct dependencies that introduce them.
#[derive(Debug, Clone, Default)]
pub struct ResolutionGuideView {
    /// Resolution entries for vulnerable transitive dependencies
    pub entries: Vec<ResolutionEntryView>,
}

/// View representation of a single resolution entry
///
/// Maps a vulnerable transitive package to the direct dependency(ies)
/// that pull it in, along with vulnerability details.
#[derive(Debug, Clone)]
pub struct ResolutionEntryView {
    /// Name of the vulnerable transitive package
    pub vulnerable_package: String,
    /// Current installed version of the vulnerable package
    pub current_version: String,
    /// Version that fixes the vulnerability (if available)
    pub fixed_version: Option<String>,
    /// Severity of the vulnerability
    pub severity: SeverityView,
    /// Vulnerability ID (e.g., CVE-2024-XXXXX)
    pub vulnerability_id: String,
    /// Direct dependencies that introduce this vulnerable package
    pub introduced_by: Vec<IntroducedByView>,
    /// Full dependency chains from direct deps to the vulnerable package.
    /// Each inner Vec is [direct_dep, ..., vulnerable_package].
    /// Populated by the builder (Issue #498) and rendered in the Markdown
    /// "Dependency Chains" subsection when chains are multi-hop (len > 2).
    pub dependency_chains: Vec<Vec<String>>,
}

/// View representation of a direct dependency that introduces a vulnerable package
#[derive(Debug, Clone)]
pub struct IntroducedByView {
    /// Name of the direct dependency
    pub package_name: String,
    /// Current version of the direct dependency
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolution_guide_view_default() {
        let view = ResolutionGuideView::default();
        assert!(view.entries.is_empty());
    }

    #[test]
    fn test_resolution_entry_view_creation() {
        let entry = ResolutionEntryView {
            vulnerable_package: "urllib3".to_string(),
            current_version: "1.26.5".to_string(),
            fixed_version: Some("1.26.18".to_string()),
            severity: SeverityView::High,
            vulnerability_id: "CVE-2023-43804".to_string(),
            introduced_by: vec![IntroducedByView {
                package_name: "requests".to_string(),
                version: "2.28.0".to_string(),
            }],
            dependency_chains: vec![vec!["requests".to_string(), "urllib3".to_string()]],
        };

        assert_eq!(entry.vulnerable_package, "urllib3");
        assert_eq!(entry.current_version, "1.26.5");
        assert_eq!(entry.fixed_version, Some("1.26.18".to_string()));
        assert_eq!(entry.severity, SeverityView::High);
        assert_eq!(entry.vulnerability_id, "CVE-2023-43804");
        assert_eq!(entry.introduced_by.len(), 1);
        assert_eq!(entry.introduced_by[0].package_name, "requests");
        assert_eq!(entry.introduced_by[0].version, "2.28.0");
        assert_eq!(entry.dependency_chains.len(), 1);
        assert_eq!(entry.dependency_chains[0], ["requests", "urllib3"]);
    }

    #[test]
    fn test_resolution_entry_view_without_fixed_version() {
        let entry = ResolutionEntryView {
            vulnerable_package: "some-pkg".to_string(),
            current_version: "0.1.0".to_string(),
            fixed_version: None,
            severity: SeverityView::Critical,
            vulnerability_id: "CVE-2024-0001".to_string(),
            introduced_by: vec![],
            dependency_chains: vec![],
        };

        assert_eq!(entry.fixed_version, None);
        assert_eq!(entry.severity, SeverityView::Critical);
        assert!(entry.introduced_by.is_empty());
        assert!(entry.dependency_chains.is_empty());
    }

    #[test]
    fn test_introduced_by_view_creation() {
        let view = IntroducedByView {
            package_name: "requests".to_string(),
            version: "2.28.0".to_string(),
        };

        assert_eq!(view.package_name, "requests");
        assert_eq!(view.version, "2.28.0");
    }
}
