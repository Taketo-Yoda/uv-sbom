use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct Bom {
    #[serde(rename = "bomFormat")]
    pub(super) bom_format: String,
    #[serde(rename = "specVersion")]
    pub(super) spec_version: String,
    pub(super) version: u32,
    #[serde(rename = "serialNumber")]
    pub(super) serial_number: String,
    pub(super) metadata: Metadata,
    pub(super) components: Vec<Component>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dependencies: Option<Vec<Dependency>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) vulnerabilities: Option<Vec<Vulnerability>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) properties: Option<Vec<Property>>,
}

#[derive(Debug, Serialize)]
pub(super) struct Property {
    pub(super) name: String,
    pub(super) value: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Dependency {
    #[serde(rename = "ref")]
    pub(super) bom_ref: String,
    #[serde(rename = "dependsOn", skip_serializing_if = "Vec::is_empty")]
    pub(super) depends_on: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct Vulnerability {
    #[serde(rename = "bom-ref")]
    pub(super) bom_ref: String,
    pub(super) id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) source: Option<VulnerabilitySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) ratings: Option<Vec<Rating>>,
    pub(super) affects: Vec<Affect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) properties: Option<Vec<Property>>,
}

#[derive(Debug, Serialize)]
pub(super) struct VulnerabilitySource {
    pub(super) url: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Rating {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) score: Option<f32>,
    pub(super) severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) vector: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct Affect {
    #[serde(rename = "ref")]
    pub(super) bom_ref: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Metadata {
    pub(super) timestamp: String,
    pub(super) tools: Vec<Tool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) component: Option<MetadataComponent>,
}

#[derive(Debug, Serialize)]
pub(super) struct MetadataComponent {
    #[serde(rename = "type")]
    pub(super) component_type: String,
    #[serde(rename = "bom-ref")]
    pub(super) bom_ref: String,
    pub(super) name: String,
    pub(super) version: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Tool {
    pub(super) name: String,
    pub(super) version: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Component {
    #[serde(rename = "type")]
    pub(super) component_type: String,
    #[serde(rename = "bom-ref")]
    pub(super) bom_ref: String,
    pub(super) group: String,
    pub(super) name: String,
    pub(super) version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hashes: Option<Vec<Hash>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) licenses: Option<Vec<License>>,
    pub(super) purl: String,
}

#[derive(Debug, Serialize)]
pub(super) struct Hash {
    pub(super) alg: String,
    pub(super) content: String,
}

#[derive(Debug, Serialize)]
pub(super) struct License {
    pub(super) license: LicenseContent,
}

#[derive(Debug, Serialize)]
pub(super) struct LicenseContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
}
