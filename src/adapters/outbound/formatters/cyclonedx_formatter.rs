use crate::application::read_models::{
    ComponentView, DependencyView, LicenseView, SbomMetadataView, SbomReadModel,
    VulnerabilityReportView, VulnerabilityView,
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
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<License>>,
    purl: String,
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
                .map(|v| self.build_vulnerabilities(v)),
        };

        serde_json::to_string_pretty(&bom).map_err(Into::into)
    }
}

impl CycloneDxFormatter {
    /// Build metadata from SbomMetadataView
    fn build_metadata(&self, metadata: &SbomMetadataView) -> Metadata {
        Metadata {
            timestamp: metadata.timestamp.clone(),
            tools: vec![Tool {
                name: metadata.tool_name.clone(),
                version: metadata.tool_version.clone(),
            }],
        }
    }

    /// Build components from ComponentView slice
    fn build_components(&self, components: &[ComponentView]) -> Vec<Component> {
        components
            .iter()
            .map(|c| {
                let licenses = c.license.as_ref().map(|l| self.build_license(l));
                Component {
                    component_type: "library".to_string(),
                    name: c.name.clone(),
                    version: c.version.clone(),
                    description: c.description.clone(),
                    licenses,
                    purl: c.purl.clone(),
                }
            })
            .collect()
    }

    /// Build license from LicenseView
    fn build_license(&self, license: &LicenseView) -> Vec<License> {
        vec![License {
            license: LicenseContent {
                id: license.spdx_id.clone(),
                name: Some(license.name.clone()),
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
    fn build_vulnerabilities(&self, report: &VulnerabilityReportView) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Process actionable vulnerabilities
        for vuln in &report.actionable {
            vulnerabilities.push(self.build_vulnerability(vuln));
        }

        // Process informational vulnerabilities
        for vuln in &report.informational {
            vulnerabilities.push(self.build_vulnerability(vuln));
        }

        vulnerabilities
    }

    /// Build a single vulnerability from VulnerabilityView
    fn build_vulnerability(&self, vuln: &VulnerabilityView) -> Vulnerability {
        let source = vuln
            .source_url
            .as_ref()
            .map(|url| VulnerabilitySource { url: url.clone() });

        let ratings = Some(vec![Rating {
            score: vuln.cvss_score,
            severity: vuln.severity.as_str().to_string(),
            vector: vuln.cvss_vector.clone(),
        }]);

        Vulnerability {
            bom_ref: vuln.bom_ref.clone(),
            id: vuln.id.clone(),
            description: vuln.description.clone(),
            source,
            ratings,
            affects: vec![Affect {
                bom_ref: vuln.affected_component.clone(),
            }],
        }
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
    fn test_format_with_license() {
        let model = create_test_read_model();
        let formatter = CycloneDxFormatter::new();

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"licenses\""));
        assert!(json.contains("Apache-2.0"));
        assert!(json.contains("Apache License 2.0"));
    }
}
