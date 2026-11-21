use crate::application::read_models::{
    ConstraintOutcomeView, ConstraintSuggestionView, IntroducedByView, UpgradeEntryView,
    UpgradeRecommendationView, VulnerabilityView,
};
use crate::i18n::Messages;

fn format_constraint_suggestion(
    messages: &'static Messages,
    suggestion: &ConstraintSuggestionView,
) -> String {
    match &suggestion.outcome {
        ConstraintOutcomeView::Verified { resolved_version } => Messages::format(
            messages.action_constraint_verified,
            &[
                &suggestion.package_name,
                &suggestion.min_version,
                resolved_version,
            ],
        ),
        ConstraintOutcomeView::DoesNotResolve { reason } => Messages::format(
            messages.action_constraint_does_not_resolve,
            &[&suggestion.package_name, &suggestion.min_version, reason],
        ),
        ConstraintOutcomeView::SimulationFailed { error } => Messages::format(
            messages.action_constraint_simulation_failed,
            &[&suggestion.package_name, &suggestion.min_version, error],
        ),
    }
}

/// Counts unique affected packages from a list of vulnerability views
pub(super) fn count_unique_packages(vulns: &[VulnerabilityView]) -> usize {
    let unique: std::collections::HashSet<&str> = vulns
        .iter()
        .map(|v| v.affected_component.as_str())
        .collect();
    unique.len().max(1)
}

/// Finds the recommended action text for a resolution entry from upgrade recommendations.
///
/// Matches by `vulnerability_id` for `Upgradable`/`Unresolvable` variants, and falls back
/// to matching by direct dependency name for `SimulationFailed`.
pub(super) fn find_upgrade_action(
    messages: &'static Messages,
    recommendations: &UpgradeRecommendationView,
    vulnerability_id: &str,
    introduced_by: &[IntroducedByView],
) -> String {
    for rec in &recommendations.entries {
        match rec {
            UpgradeEntryView::Upgradable {
                direct_dep,
                target_version,
                transitive_dep,
                resolved_version,
                vulnerability_id: vid,
                ..
            } if vid == vulnerability_id => {
                return Messages::format(
                    messages.action_upgrade,
                    &[direct_dep, target_version, transitive_dep, resolved_version],
                );
            }
            UpgradeEntryView::Unresolvable {
                direct_dep_name,
                transitive_dep_name,
                fixed_version,
                reason,
                vulnerability_id: vid,
                constraint_suggestion,
            } if vid == vulnerability_id => {
                let _ = (direct_dep_name, transitive_dep_name, fixed_version);
                let mut text = Messages::format(messages.action_cannot_resolve, &[reason]);
                if let Some(suggestion) = constraint_suggestion {
                    text.push(' ');
                    text.push_str(&format_constraint_suggestion(messages, suggestion));
                }
                return text;
            }
            _ => {}
        }
    }

    let introduced_names: Vec<&str> = introduced_by
        .iter()
        .map(|ib| ib.package_name.as_str())
        .collect();
    for rec in &recommendations.entries {
        if let UpgradeEntryView::SimulationFailed { direct_dep, error } = rec {
            if introduced_names.contains(&direct_dep.as_str()) {
                return Messages::format(messages.action_could_not_analyze, &[error]);
            }
        }
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{SeverityView, VulnerabilityView};

    #[test]
    fn test_count_unique_packages() {
        let vulns = vec![
            VulnerabilityView {
                bom_ref: "v1".to_string(),
                id: "CVE-1".to_string(),
                affected_component: "pkg:pypi/a@1.0".to_string(),
                affected_component_name: "a".to_string(),
                affected_version: "1.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: None,
                description: None,
                source_url: None,
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
            },
            VulnerabilityView {
                bom_ref: "v2".to_string(),
                id: "CVE-2".to_string(),
                affected_component: "pkg:pypi/a@1.0".to_string(),
                affected_component_name: "a".to_string(),
                affected_version: "1.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::Medium,
                fixed_version: None,
                description: None,
                source_url: None,
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
            },
            VulnerabilityView {
                bom_ref: "v3".to_string(),
                id: "CVE-3".to_string(),
                affected_component: "pkg:pypi/b@2.0".to_string(),
                affected_component_name: "b".to_string(),
                affected_version: "2.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::Low,
                fixed_version: None,
                description: None,
                source_url: None,
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
            },
        ];

        assert_eq!(count_unique_packages(&vulns), 2);
    }
}
