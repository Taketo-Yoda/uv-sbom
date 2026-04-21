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
}
