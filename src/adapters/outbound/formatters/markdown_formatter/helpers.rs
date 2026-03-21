use crate::application::read_models::{
    IntroducedByView, UpgradeEntryView, UpgradeRecommendationView, VulnerabilityView,
};
use crate::i18n::Messages;

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
                reason,
                vulnerability_id: vid,
                ..
            } if vid == vulnerability_id => {
                return Messages::format(messages.action_cannot_resolve, &[reason]);
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
            },
        ];

        assert_eq!(count_unique_packages(&vulns), 2);
    }
}
