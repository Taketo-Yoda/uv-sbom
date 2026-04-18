use super::super::schema::Property;
use crate::application::read_models::{
    LicenseComplianceView, ResolutionGuideView, UpgradeEntryView, UpgradeRecommendationView,
    VulnerabilityView,
};

/// Build vulnerability [`Property`] entries from a resolution guide and upgrade recommendations.
///
/// Returns `None` when no properties are applicable for the given vulnerability.
pub(in super::super) fn from_resolution_guide(
    vuln: &VulnerabilityView,
    resolution_guide: Option<&ResolutionGuideView>,
    upgrade_recommendations: Option<&UpgradeRecommendationView>,
) -> Option<Vec<Property>> {
    let mut properties: Vec<Property> = resolution_guide
        .and_then(|guide| {
            let entry = guide.entries.iter().find(|e| {
                e.vulnerability_id == vuln.id
                    && e.vulnerable_package == vuln.affected_component_name
            });
            entry.map(|e| {
                e.introduced_by
                    .iter()
                    .map(|ib| Property {
                        name: "uv-sbom:introduced-by".to_string(),
                        value: format!("{}@{}", ib.package_name, ib.version),
                    })
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();

    if let Some(recommendations) = upgrade_recommendations {
        for rec in &recommendations.entries {
            match rec {
                UpgradeEntryView::Upgradable {
                    direct_dep,
                    target_version,
                    transitive_dep,
                    resolved_version,
                    vulnerability_id,
                    ..
                } if vulnerability_id == &vuln.id => {
                    properties.push(Property {
                        name: "uv-sbom:recommended-action".to_string(),
                        value: format!("upgrade {} to {}", direct_dep, target_version),
                    });
                    properties.push(Property {
                        name: "uv-sbom:resolved-version".to_string(),
                        value: format!("{}@{}", transitive_dep, resolved_version),
                    });
                    break;
                }
                UpgradeEntryView::Unresolvable {
                    reason,
                    vulnerability_id,
                    ..
                } if vulnerability_id == &vuln.id => {
                    properties.push(Property {
                        name: "uv-sbom:recommended-action".to_string(),
                        value: format!("cannot resolve: {}", reason),
                    });
                    break;
                }
                _ => {}
            }
        }
    }

    if properties.is_empty() {
        None
    } else {
        Some(properties)
    }
}

/// Build BOM-level [`Property`] entries for license compliance information.
pub(in super::super) fn from_license_compliance(
    compliance: &LicenseComplianceView,
) -> Vec<Property> {
    let mut props = Vec::new();

    let status = if compliance.has_violations {
        "FAIL"
    } else {
        "PASS"
    };
    props.push(Property {
        name: "uv-sbom:license-compliance:status".to_string(),
        value: status.to_string(),
    });

    props.push(Property {
        name: "uv-sbom:license-compliance:violation-count".to_string(),
        value: compliance.summary.violation_count.to_string(),
    });

    props.push(Property {
        name: "uv-sbom:license-compliance:warning-count".to_string(),
        value: compliance.summary.warning_count.to_string(),
    });

    for v in &compliance.violations {
        let detail = format!(
            "{}@{}: {} ({})",
            v.package_name, v.package_version, v.license, v.reason,
        );
        props.push(Property {
            name: "uv-sbom:license-compliance:violation".to_string(),
            value: detail,
        });
    }

    props
}
