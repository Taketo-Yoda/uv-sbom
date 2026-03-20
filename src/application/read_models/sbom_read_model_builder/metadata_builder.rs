use crate::sbom_generation::domain::SbomMetadata;

use super::super::sbom_read_model::{MetadataComponentView, SbomMetadataView};

pub(super) fn build_metadata(
    metadata: &SbomMetadata,
    project_component: Option<(&str, &str)>,
) -> SbomMetadataView {
    SbomMetadataView {
        timestamp: metadata.timestamp().to_string(),
        tool_name: metadata.tool_name().to_string(),
        tool_version: metadata.tool_version().to_string(),
        serial_number: metadata.serial_number().to_string(),
        component: project_component.map(|(name, version)| MetadataComponentView {
            name: name.to_string(),
            version: version.to_string(),
        }),
    }
}
