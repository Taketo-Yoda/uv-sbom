use super::super::resolution_guide_view::{
    IntroducedByView, ResolutionEntryView, ResolutionGuideView,
};
use crate::sbom_generation::domain::resolution_guide::ResolutionEntry;

/// Builds resolution guide view from domain resolution entries
///
/// Converts domain `ResolutionEntry` values into view-optimized
/// `ResolutionEntryView` structs.
pub(super) fn build_resolution_guide(entries: &[ResolutionEntry]) -> ResolutionGuideView {
    let entry_views: Vec<ResolutionEntryView> =
        entries.iter().map(build_resolution_entry_view).collect();

    ResolutionGuideView {
        entries: entry_views,
    }
}

/// Converts a single domain ResolutionEntry to a view
fn build_resolution_entry_view(entry: &ResolutionEntry) -> ResolutionEntryView {
    let introduced_by: Vec<IntroducedByView> = entry
        .introduced_by()
        .iter()
        .map(|ib| IntroducedByView {
            package_name: ib.package_name().to_string(),
            version: ib.version().to_string(),
        })
        .collect();

    let dependency_chains = entry.dependency_chains().to_vec();

    ResolutionEntryView {
        vulnerable_package: entry.vulnerable_package().to_string(),
        current_version: entry.current_version().to_string(),
        fixed_version: entry.fixed_version().map(|v| v.to_string()),
        severity: super::vulnerability_builder::map_severity(&entry.severity()),
        vulnerability_id: entry.vulnerability_id().to_string(),
        introduced_by,
        dependency_chains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::sbom_read_model_builder::test_helpers as th;
    use crate::application::read_models::vulnerability_view::SeverityView;
    use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
    use crate::sbom_generation::domain::vulnerability::Severity;

    fn make_entry(pkg: &str, version: &str, chains: Vec<Vec<String>>) -> ResolutionEntry {
        ResolutionEntry::new(
            pkg.to_string(),
            version.to_string(),
            None,
            Severity::High,
            "CVE-2024-0001".to_string(),
            vec![IntroducedBy::new("parent".to_string(), "1.0.0".to_string())],
            chains,
        )
    }

    #[test]
    fn test_build_resolution_entry_view_maps_dependency_chains() {
        let chains = vec![
            vec!["requests".to_string(), "urllib3".to_string()],
            vec!["httpx".to_string(), "urllib3".to_string()],
        ];
        let entry = make_entry("urllib3", "1.26.5", chains.clone());

        let view = build_resolution_entry_view(&entry);

        assert_eq!(view.dependency_chains, chains);
    }

    #[test]
    fn test_build_resolution_entry_view_empty_dependency_chains() {
        let entry = make_entry("urllib3", "1.26.5", vec![]);

        let view = build_resolution_entry_view(&entry);

        assert!(view.dependency_chains.is_empty());
    }

    #[test]
    fn test_build_resolution_guide_propagates_chains() {
        let entries = vec![
            make_entry(
                "urllib3",
                "1.26.5",
                vec![vec!["requests".to_string(), "urllib3".to_string()]],
            ),
            make_entry("certifi", "2023.7.22", vec![]),
        ];

        let guide = build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 2);
        assert_eq!(guide.entries[0].dependency_chains.len(), 1);
        assert!(guide.entries[1].dependency_chains.is_empty());
    }

    #[test]
    fn test_build_resolution_guide_converts_entries() {
        let entries = vec![th::resolution_entry(
            "urllib3",
            "1.26.5",
            Some("1.26.18"),
            Severity::High,
            "CVE-2023-43804",
            &[("requests", "2.28.0")],
        )];

        let guide = build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].vulnerable_package, "urllib3");
        assert_eq!(guide.entries[0].current_version, "1.26.5");
        assert_eq!(guide.entries[0].fixed_version, Some("1.26.18".to_string()));
        assert_eq!(guide.entries[0].severity, SeverityView::High);
        assert_eq!(guide.entries[0].vulnerability_id, "CVE-2023-43804");
        assert_eq!(guide.entries[0].introduced_by.len(), 1);
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "requests");
        assert_eq!(guide.entries[0].introduced_by[0].version, "2.28.0");
    }

    #[test]
    fn test_build_resolution_guide_without_fixed_version() {
        let entries = vec![th::resolution_entry(
            "vulnerable-pkg",
            "0.1.0",
            None,
            Severity::Critical,
            "CVE-2024-0001",
            &[("parent-pkg", "1.0.0")],
        )];

        let guide = build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].fixed_version, None);
        assert_eq!(guide.entries[0].severity, SeverityView::Critical);
    }

    #[test]
    fn test_build_resolution_guide_multiple_introduced_by() {
        let entries = vec![th::resolution_entry(
            "urllib3",
            "1.26.5",
            Some("1.26.18"),
            Severity::High,
            "CVE-2023-43804",
            &[("httpx", "0.23.0"), ("requests", "2.28.0")],
        )];

        let guide = build_resolution_guide(&entries);

        assert_eq!(guide.entries[0].introduced_by.len(), 2);
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "httpx");
        assert_eq!(guide.entries[0].introduced_by[1].package_name, "requests");
    }
}
