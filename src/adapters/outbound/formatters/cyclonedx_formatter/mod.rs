mod builders;
mod schema;
use schema::*;

use crate::application::read_models::SbomReadModel;
use crate::ports::outbound::SbomFormatter;
use crate::shared::Result;

/// CycloneDxFormatter adapter for generating CycloneDX 1.6 JSON format
///
/// This adapter implements the SbomFormatter port for CycloneDX format.
pub struct CycloneDxFormatter;

impl CycloneDxFormatter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CycloneDxFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomFormatter for CycloneDxFormatter {
    fn format(&self, model: &SbomReadModel) -> Result<String> {
        let properties = model
            .license_compliance
            .as_ref()
            .map(builders::property::from_license_compliance);

        let bom = Bom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            serial_number: model.metadata.serial_number.clone(),
            metadata: builders::metadata::build(&model.metadata),
            components: builders::component::build_all(&model.components),
            dependencies: model.dependencies.as_ref().map(builders::dependency::build),
            vulnerabilities: model.vulnerabilities.as_ref().map(|v| {
                builders::vulnerability::build_all(
                    v,
                    model.resolution_guide.as_ref(),
                    model.upgrade_recommendations.as_ref(),
                )
            }),
            properties,
        };

        serde_json::to_string_pretty(&bom).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        ComponentView, DependencyView, LicenseView, SbomMetadataView, SeverityView,
        VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
    };
    use std::collections::HashMap;

    fn create_test_read_model() -> SbomReadModel {
        SbomReadModel {
            metadata: SbomMetadataView {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                tool_name: "uv-sbom".to_string(),
                tool_version: "1.0.0".to_string(),
                serial_number: "urn:uuid:test-123".to_string(),
                component: None,
            },
            components: vec![
                ComponentView {
                    bom_ref: "pkg:pypi/requests@2.31.0".to_string(),
                    name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                    purl: "pkg:pypi/requests@2.31.0".to_string(),
                    license: Some(LicenseView {
                        spdx_id: Some("Apache-2.0".to_string()),
                        name: "Apache License 2.0".to_string(),
                        url: None,
                    }),
                    description: Some("HTTP library".to_string()),
                    sha256_hash: None,
                    is_direct_dependency: true,
                },
                ComponentView {
                    bom_ref: "pkg:pypi/numpy@1.24.0".to_string(),
                    name: "numpy".to_string(),
                    version: "1.24.0".to_string(),
                    purl: "pkg:pypi/numpy@1.24.0".to_string(),
                    license: None,
                    description: Some("Array library".to_string()),
                    sha256_hash: None,
                    is_direct_dependency: false,
                },
            ],
            dependencies: None,
            vulnerabilities: None,
            license_compliance: None,
            resolution_guide: None,
            upgrade_recommendations: None,
        }
    }

    #[test]
    fn test_format_basic() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(json.contains("\"specVersion\": \"1.6\""));
        assert!(json.contains("\"serialNumber\": \"urn:uuid:test-123\""));
        assert!(json.contains("\"name\": \"uv-sbom\""));
        assert!(json.contains("requests"));
        assert!(json.contains("numpy"));
    }

    #[test]
    fn test_format_with_dependencies() {
        let mut model = create_test_read_model();
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );

        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        });

        let formatter = CycloneDxFormatter::new();
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"dependencies\""));
        assert!(json.contains("\"dependsOn\""));
        assert!(json.contains("urllib3"));
    }

    #[test]
    fn test_format_with_vulnerabilities() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()),
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: Some("Test vulnerability".to_string()),
                source_url: Some("https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()),
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        let formatter = CycloneDxFormatter::new();
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"vulnerabilities\""));
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("\"severity\": \"HIGH\""));
        assert!(json.contains("\"score\": 7.5"));
    }

    #[test]
    fn test_format_with_license_spdx_id() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"licenses\""));
        // When SPDX ID is present, only id is output (no name)
        assert!(json.contains("\"id\": \"Apache-2.0\""));
        assert!(!json.contains("\"name\": \"Apache License 2.0\""));
    }

    #[test]
    fn test_format_with_license_fallback_to_name() {
        let mut model = create_test_read_model();
        model.components[0].license = Some(LicenseView {
            spdx_id: None,
            name: "Some Proprietary License".to_string(),
            url: None,
        });
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"name\": \"Some Proprietary License\""));
        assert!(!json.contains("\"id\""));
    }

    #[test]
    fn test_format_with_group_field() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"group\": \"pypi\""));
    }

    #[test]
    fn test_format_with_bom_ref_field() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"bom-ref\": \"pkg:pypi/requests@2.31.0\""));
    }

    // ============================================================
    // Resolution guide property tests
    // ============================================================

    #[test]
    fn test_format_with_resolution_guide_properties() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                fixed_version: Some("2.32.0".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-1234".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "my-app".to_string(),
                    version: "1.0.0".to_string(),
                }],
            }],
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("\"uv-sbom:introduced-by\""));
        assert!(json.contains("my-app@1.0.0"));
    }

    #[test]
    fn test_format_with_resolution_guide_multiple_introduced_by() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                fixed_version: Some("2.32.0".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-1234".to_string(),
                introduced_by: vec![
                    IntroducedByView {
                        package_name: "my-app".to_string(),
                        version: "1.0.0".to_string(),
                    },
                    IntroducedByView {
                        package_name: "other-app".to_string(),
                        version: "2.0.0".to_string(),
                    },
                ],
            }],
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("my-app@1.0.0"));
        assert!(json.contains("other-app@2.0.0"));
    }

    // ============================================================
    // Hash tests
    // ============================================================

    #[test]
    fn test_format_with_hashes() {
        let mut model = create_test_read_model();
        model.components[0].sha256_hash =
            Some("942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1".to_string());

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("\"hashes\""));
        assert!(json.contains("\"alg\": \"SHA-256\""));
        assert!(json.contains(
            "\"content\": \"942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1\""
        ));
    }

    #[test]
    fn test_format_without_hashes_omits_field() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        // Components without sha256_hash should not have hashes field
        assert!(!json.contains("\"hashes\""));
    }

    // ============================================================
    // Metadata component tests
    // ============================================================

    #[test]
    fn test_format_with_metadata_component() {
        use crate::application::read_models::MetadataComponentView;

        let mut model = create_test_read_model();
        model.metadata.component = Some(MetadataComponentView {
            name: "my-project".to_string(),
            version: "1.0.0".to_string(),
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("\"type\": \"application\""));
        assert!(json.contains("\"bom-ref\": \"my-project-1.0.0\""));
        assert!(json.contains("\"name\": \"my-project\""));
        assert!(json.contains("\"version\": \"1.0.0\""));
    }

    #[test]
    fn test_format_without_metadata_component() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        // metadata should not contain component field when None
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["metadata"]["component"].is_null());
    }

    #[test]
    fn test_format_vulnerability_no_resolution_guide() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        // No properties field when no resolution guide
        assert!(!json.contains("\"uv-sbom:introduced-by\""));
    }

    // ============================================================
    // Upgrade recommendation property tests
    // ============================================================

    #[test]
    fn test_format_with_upgrade_recommendation_upgradable() {
        use crate::application::read_models::{UpgradeEntryView, UpgradeRecommendationView};

        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Upgradable {
                direct_dep: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                target_version: "2.32.3".to_string(),
                transitive_dep: "urllib3".to_string(),
                resolved_version: "2.2.1".to_string(),
                vulnerability_id: "CVE-2024-1234".to_string(),
            }],
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("\"uv-sbom:recommended-action\""));
        assert!(json.contains("\"upgrade requests to 2.32.3\""));
        assert!(json.contains("\"uv-sbom:resolved-version\""));
        assert!(json.contains("\"urllib3@2.2.1\""));
    }

    #[test]
    fn test_format_with_upgrade_recommendation_unresolvable() {
        use crate::application::read_models::{UpgradeEntryView, UpgradeRecommendationView};

        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Unresolvable {
                direct_dep: "requests".to_string(),
                reason: "no compatible version available".to_string(),
                vulnerability_id: "CVE-2024-1234".to_string(),
            }],
        });

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(json.contains("\"uv-sbom:recommended-action\""));
        assert!(json.contains("\"cannot resolve: no compatible version available\""));
        assert!(!json.contains("\"uv-sbom:resolved-version\""));
    }

    #[test]
    fn test_format_without_upgrade_recommendations_no_extra_properties() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(7.5),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });
        // upgrade_recommendations is None

        let formatter = CycloneDxFormatter::new();
        let json = formatter.format(&model).unwrap();

        assert!(!json.contains("\"uv-sbom:recommended-action\""));
        assert!(!json.contains("\"uv-sbom:resolved-version\""));
    }
}
