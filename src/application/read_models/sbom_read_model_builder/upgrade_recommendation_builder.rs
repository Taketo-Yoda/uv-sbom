use super::super::upgrade_recommendation_view::{UpgradeEntryView, UpgradeRecommendationView};
use crate::sbom_generation::domain::UpgradeRecommendation;

/// Maps a slice of domain UpgradeRecommendation to an UpgradeRecommendationView
pub(super) fn build_upgrade_recommendations(
    recommendations: &[UpgradeRecommendation],
) -> UpgradeRecommendationView {
    let entries = recommendations
        .iter()
        .map(|rec| match rec {
            UpgradeRecommendation::Upgradable {
                direct_dep_name,
                direct_dep_target_version,
                transitive_dep_name,
                transitive_resolved_version,
                vulnerability_id,
                ..
            } => UpgradeEntryView::Upgradable {
                direct_dep: direct_dep_name.clone(),
                target_version: direct_dep_target_version.clone(),
                transitive_dep: transitive_dep_name.clone(),
                resolved_version: transitive_resolved_version.clone(),
                vulnerability_id: vulnerability_id.clone(),
            },
            UpgradeRecommendation::Unresolvable {
                reason,
                vulnerability_id,
                ..
            } => UpgradeEntryView::Unresolvable {
                reason: reason.clone(),
                vulnerability_id: vulnerability_id.clone(),
            },
            UpgradeRecommendation::SimulationFailed {
                direct_dep_name,
                error,
            } => UpgradeEntryView::SimulationFailed {
                direct_dep: direct_dep_name.clone(),
                error: error.clone(),
            },
        })
        .collect();

    UpgradeRecommendationView { entries }
}
