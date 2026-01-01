/// SbomMetadata value object representing SBOM metadata
#[derive(Debug, Clone)]
pub struct SbomMetadata {
    timestamp: String,
    tool_name: String,
    tool_version: String,
    serial_number: String,
}

impl SbomMetadata {
    pub fn new(
        timestamp: String,
        tool_name: String,
        tool_version: String,
        serial_number: String,
    ) -> Self {
        Self {
            timestamp,
            tool_name,
            tool_version,
            serial_number,
        }
    }

    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }

    pub fn serial_number(&self) -> &str {
        &self.serial_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbom_metadata_new() {
        let metadata = SbomMetadata::new(
            "2024-01-01T00:00:00Z".to_string(),
            "uv-sbom".to_string(),
            "0.1.0".to_string(),
            "urn:uuid:12345".to_string(),
        );

        assert_eq!(metadata.timestamp(), "2024-01-01T00:00:00Z");
        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), "0.1.0");
        assert_eq!(metadata.serial_number(), "urn:uuid:12345");
    }
}
