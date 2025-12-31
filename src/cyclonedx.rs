use crate::lockfile::Package;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct Bom {
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

pub fn generate_bom(packages: Vec<Package>) -> Result<Bom> {
    let components: Vec<Component> = packages
        .into_iter()
        .map(|pkg| {
            let purl = format!("pkg:pypi/{}@{}", pkg.name, pkg.version);

            let licenses = pkg.license.map(|license_name| {
                vec![License {
                    license: LicenseContent {
                        id: None,
                        name: Some(license_name),
                    },
                }]
            });

            Component {
                component_type: "library".to_string(),
                name: pkg.name,
                version: pkg.version,
                description: pkg.description,
                licenses,
                purl,
            }
        })
        .collect();

    let bom = Bom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.6".to_string(),
        version: 1,
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        metadata: Metadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![Tool {
                name: "uv-sbom".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }],
        },
        components,
    };

    Ok(bom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bom() {
        let packages = vec![
            Package {
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
                description: Some("HTTP library".to_string()),
                license: Some("Apache 2.0".to_string()),
            },
            Package {
                name: "numpy".to_string(),
                version: "1.24.0".to_string(),
                description: Some("Array library".to_string()),
                license: None,
            },
        ];

        let bom = generate_bom(packages).unwrap();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.6");
        assert_eq!(bom.components.len(), 2);
        assert_eq!(bom.components[0].name, "requests");
        assert_eq!(bom.components[1].name, "numpy");
    }
}
