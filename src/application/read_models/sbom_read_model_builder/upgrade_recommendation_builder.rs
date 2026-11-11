use super::super::upgrade_recommendation_view::{
    ConstraintOutcomeView, ConstraintSuggestionView, UpgradeEntryView, UpgradeRecommendationView,
};
use crate::sbom_generation::domain::upgrade_recommendation::{
    ConstraintOutcome, ConstraintSuggestion,
};
use crate::sbom_generation::domain::UpgradeRecommendation;

fn map_constraint_suggestion(cs: &ConstraintSuggestion) -> ConstraintSuggestionView {
    ConstraintSuggestionView {
        package_name: cs.package_name.clone(),
        min_version: cs.min_version.clone(),
        outcome: match &cs.outcome {
            ConstraintOutcome::Verified { resolved_version } => ConstraintOutcomeView::Verified {
                resolved_version: resolved_version.clone(),
            },
            ConstraintOutcome::DoesNotResolve { reason } => ConstraintOutcomeView::DoesNotResolve {
                reason: reason.clone(),
            },
            ConstraintOutcome::SimulationFailed { error } => {
                ConstraintOutcomeView::SimulationFailed {
                    error: error.clone(),
                }
            }
        },
    }
}

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
                direct_dep_name,
                transitive_dep_name,
                fixed_version,
                reason,
                vulnerability_id,
                constraint_suggestion,
            } => UpgradeEntryView::Unresolvable {
                direct_dep_name: direct_dep_name.clone(),
                transitive_dep_name: transitive_dep_name.clone(),
                fixed_version: fixed_version.clone(),
                reason: reason.clone(),
                vulnerability_id: vulnerability_id.clone(),
                constraint_suggestion: constraint_suggestion
                    .as_ref()
                    .map(map_constraint_suggestion),
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
