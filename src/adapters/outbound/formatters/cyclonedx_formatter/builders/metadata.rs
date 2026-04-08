use crate::application::read_models::SbomMetadataView;

use super::super::schema::{Metadata, MetadataComponent, Tool};

/// Build a CycloneDX `Metadata` from an [`SbomMetadataView`].
pub(in super::super) fn build(metadata: &SbomMetadataView) -> Metadata {
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
