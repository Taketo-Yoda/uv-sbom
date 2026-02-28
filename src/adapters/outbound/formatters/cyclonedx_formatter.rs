use crate::application::read_models::{
    ComponentView, DependencyView, LicenseComplianceView, LicenseView, ResolutionGuideView,
    SbomMetadataView, SbomReadModel, VulnerabilityReportView, VulnerabilityView,
};
use crate::ports::outbound::SbomFormatter;
use crate::shared::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Bom {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    version: u32,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    metadata: Metadata,
    components: Vec<Component>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<Vec<Dependency>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vulnerabilities: Option<Vec<Vulnerability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<Property>>,
}

#[derive(Debug, Serialize)]
struct Property {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct Dependency {
    #[serde(rename = "ref")]
    bom_ref: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Vulnerability {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<VulnerabilitySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ratings: Option<Vec<Rating>>,
    affects: Vec<Affect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<Property>>,
}

#[derive(Debug, Serialize)]
struct VulnerabilitySource {
    url: String,
}

#[derive(Debug, Serialize)]
struct Rating {
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f32>,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vector: Option<String>,
}

#[derive(Debug, Serialize)]
struct Affect {
    #[serde(rename = "ref")]
    bom_ref: String,
}

#[derive(Debug, Serialize)]
struct Metadata {
    timestamp: String,
    tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<MetadataComponent>,
}

#[derive(Debug, Serialize)]
struct MetadataComponent {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct Tool {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct Component {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    group: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<Hash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<License>>,
    purl: String,
}

#[derive(Debug, Serialize)]
struct Hash {
    alg: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct License {
    license: LicenseContent,
}

#[derive(Debug, Serialize)]
struct LicenseContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

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
            .map(|lc| self.build_license_compliance_properties(lc));

        let bom = Bom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            serial_number: model.metadata.serial_number.clone(),
            metadata: self.build_metadata(&model.metadata),
            components: self.build_components(&model.components),
            dependencies: model
                .dependencies
                .as_ref()
                .map(|d| self.build_dependencies(d)),
            vulnerabilities: model
                .vulnerabilities
                .as_ref()
                .map(|v| self.build_vulnerabilities(v, model.resolution_guide.as_ref())),
            properties,
        };

        serde_json::to_string_pretty(&bom).map_err(Into::into)
    }
}

impl CycloneDxFormatter {
    /// Build metadata from SbomMetadataView
    fn build_metadata(&self, metadata: &SbomMetadataView) -> Metadata {
        let component = metadata.component.as_ref().map(|c| MetadataComponent {
            component_type: "application".to_string(),
            bom_ref: format!("{}-{}", c.name, c.version),
            name: c.name.clone(),
            version: c.version.clone(),
        });

        Metadata {
            timestamp: metadata.timestamp.clone(),
            tools: vec![Tool {
                name: metadata.tool_name.clone(),
                version: metadata.tool_version.clone(),
            }],
            component,
        }
    }

    /// Build components from ComponentView slice
    fn build_components(&self, components: &[ComponentView]) -> Vec<Component> {
        components
            .iter()
            .map(|c| {
                let licenses = c.license.as_ref().map(|l| self.build_license(l));
                let hashes = c.sha256_hash.as_ref().map(|hash| {
                    vec![Hash {
                        alg: "SHA-256".to_string(),
                        content: hash.clone(),
                    }]
                });
                Component {
                    component_type: "library".to_string(),
                    bom_ref: c.bom_ref.clone(),
                    group: "pypi".to_string(),
                    name: c.name.clone(),
                    version: c.version.clone(),
                    description: c.description.clone(),
                    hashes,
                    licenses,
                    purl: c.purl.clone(),
                }
            })
            .collect()
    }

    /// Build license from LicenseView
    ///
    /// When a SPDX license ID is available, outputs `id` only (CycloneDX spec preference).
    /// Falls back to `name` when no SPDX mapping exists.
    fn build_license(&self, license: &LicenseView) -> Vec<License> {
        vec![License {
            license: if license.spdx_id.is_some() {
                LicenseContent {
                    id: license.spdx_id.clone(),
                    name: None,
                }
            } else {
                LicenseContent {
                    id: None,
                    name: Some(license.name.clone()),
                }
            },
        }]
    }

    /// Build dependencies from DependencyView
    fn build_dependencies(&self, dep_view: &DependencyView) -> Vec<Dependency> {
        let mut dependencies = Vec::new();

        // Add direct dependencies
        for direct_ref in &dep_view.direct {
            let depends_on = dep_view
                .transitive
                .get(direct_ref)
                .cloned()
                .unwrap_or_default();
            dependencies.push(Dependency {
                bom_ref: direct_ref.clone(),
                depends_on,
            });
        }

        // Add transitive dependencies that are not direct
        for (parent_ref, children) in &dep_view.transitive {
            if !dep_view.direct.contains(parent_ref) {
                dependencies.push(Dependency {
                    bom_ref: parent_ref.clone(),
                    depends_on: children.clone(),
                });
            }
        }

        dependencies
    }

    /// Build vulnerabilities from VulnerabilityReportView
    fn build_vulnerabilities(
        &self,
        report: &VulnerabilityReportView,
        resolution_guide: Option<&ResolutionGuideView>,
    ) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Process actionable vulnerabilities
        for vuln in &report.actionable {
            vulnerabilities.push(self.build_vulnerability(vuln, resolution_guide));
        }

        // Process informational vulnerabilities
        for vuln in &report.informational {
            vulnerabilities.push(self.build_vulnerability(vuln, resolution_guide));
        }

        vulnerabilities
    }

    /// Build a single vulnerability from VulnerabilityView
    fn build_vulnerability(
        &self,
        vuln: &VulnerabilityView,
        resolution_guide: Option<&ResolutionGuideView>,
    ) -> Vulnerability {
        let source = vuln
            .source_url
            .as_ref()
            .map(|url| VulnerabilitySource { url: url.clone() });

        let ratings = Some(vec![Rating {
            score: vuln.cvss_score,
            severity: vuln.severity.as_str().to_string(),
            vector: vuln.cvss_vector.clone(),
        }]);

        let properties = resolution_guide.and_then(|guide| {
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
        });

        Vulnerability {
            bom_ref: vuln.bom_ref.clone(),
            id: vuln.id.clone(),
            description: vuln.description.clone(),
            source,
            ratings,
            affects: vec![Affect {
                bom_ref: vuln.affected_component.clone(),
            }],
            properties,
        }
    }

    /// Build BOM-level properties for license compliance info
    fn build_license_compliance_properties(
        &self,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{SeverityView, VulnerabilitySummary};
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
}
