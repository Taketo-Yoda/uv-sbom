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

#[cfg(test)]
mod tests {
    use super::super::test_helpers as th;
    use super::*;

    #[test]
    fn test_build_metadata() {
        let metadata = th::metadata();
        let view = build_metadata(&metadata, None);

        assert_eq!(view.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(view.tool_name, "uv-sbom");
        assert_eq!(view.tool_version, "0.1.0");
        assert_eq!(
            view.serial_number,
            "urn:uuid:12345678-1234-1234-1234-123456789012"
        );
        assert!(view.component.is_none());
    }

    #[test]
    fn test_build_metadata_with_project_component() {
        let metadata = th::metadata();
        let view = build_metadata(&metadata, Some(("my-project", "1.0.0")));

        assert!(view.component.is_some());
        let component = view.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }

    #[test]
    fn test_build_metadata_without_project_component() {
        let metadata = th::metadata();
        let view = build_metadata(&metadata, None);

        assert!(view.component.is_none());
    }
}
