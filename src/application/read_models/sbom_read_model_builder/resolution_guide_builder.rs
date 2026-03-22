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

    ResolutionEntryView {
        vulnerable_package: entry.vulnerable_package().to_string(),
        current_version: entry.current_version().to_string(),
        fixed_version: entry.fixed_version().map(|v| v.to_string()),
        severity: super::vulnerability_builder::map_severity(&entry.severity()),
        vulnerability_id: entry.vulnerability_id().to_string(),
        introduced_by,
    }
}
