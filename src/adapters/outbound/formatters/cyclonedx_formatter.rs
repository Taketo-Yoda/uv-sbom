use crate::ports::outbound::{EnrichedPackage, SbomFormatter};
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::SbomMetadata;
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
    fn format(
        &self,
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        // NOTE: Vulnerability data is not included in CycloneDX JSON format output.
        // The CycloneDX specification does support vulnerability information,
        // but that feature is not yet implemented in this formatter.
        // For now, only the Markdown formatter displays vulnerability information.
        _vulnerability_report: Option<&[PackageVulnerabilities]>,
    ) -> Result<String> {
        let components: Vec<Component> = packages
            .into_iter()
            .map(|enriched| {
                let pkg = enriched.package;
                let purl = format!("pkg:pypi/{}@{}", pkg.name(), pkg.version());

                let licenses = enriched.license.map(|license_name| {
                    vec![License {
                        license: LicenseContent {
                            id: None,
                            name: Some(license_name),
                        },
                    }]
                });

                Component {
                    component_type: "library".to_string(),
                    name: pkg.name().to_string(),
                    version: pkg.version().to_string(),
                    description: enriched.description,
                    licenses,
                    purl,
                }
            })
            .collect();

        let bom = Bom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            serial_number: metadata.serial_number().to_string(),
            metadata: Metadata {
                timestamp: metadata.timestamp().to_string(),
                tools: vec![Tool {
                    name: metadata.tool_name().to_string(),
                    version: metadata.tool_version().to_string(),
                }],
            },
            components,
        };

        let json = serde_json::to_string_pretty(&bom)?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::Package;
    use crate::sbom_generation::services::SbomGenerator;

    #[test]
    fn test_cyclonedx_formatter() {
        let pkg1 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let pkg2 = Package::new("numpy".to_string(), "1.24.0".to_string()).unwrap();

        let enriched = vec![
            EnrichedPackage::new(
                pkg1,
                Some("Apache 2.0".to_string()),
                Some("HTTP library".to_string()),
            ),
            EnrichedPackage::new(pkg2, None, Some("Array library".to_string())),
        ];

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let formatter = CycloneDxFormatter::new();
        let result = formatter.format(enriched, &metadata, None);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(json.contains("\"specVersion\": \"1.6\""));
        assert!(json.contains("requests"));
        assert!(json.contains("numpy"));
    }
}
