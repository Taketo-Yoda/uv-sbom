/// SbomMetadata value object representing SBOM metadata
#[derive(Debug, Clone)]
pub struct SbomMetadata {
    timestamp: String,
    tool_name: String,
    tool_version: String,
    serial_number: String,
    /// OSV data attribution for CC-BY 4.0 license compliance
    /// Only present when vulnerability data from OSV is included
    #[allow(dead_code)] // Will be used in subsequent subtasks
    osv_attribution: Option<String>,
}

impl SbomMetadata {
    pub fn new(
        timestamp: String,
        tool_name: String,
        tool_version: String,
        serial_number: String,
        osv_attribution: Option<String>,
    ) -> Self {
        Self {
            timestamp,
            tool_name,
            tool_version,
            serial_number,
            osv_attribution,
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

    #[allow(dead_code)] // Will be used in subsequent subtasks
    pub fn osv_attribution(&self) -> Option<&str> {
        self.osv_attribution.as_deref()
    }

    /// Creates metadata with OSV attribution for CC-BY 4.0 compliance
    ///
    /// Use this when vulnerability data from OSV is included in the SBOM
    pub fn with_osv_attribution(
        timestamp: String,
        tool_name: String,
        tool_version: String,
        serial_number: String,
    ) -> Self {
        Self::new(
            timestamp,
            tool_name,
            tool_version,
            serial_number,
            Some(
                "Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0".to_string(),
            ),
        )
    }

    /// Creates metadata without OSV attribution
    ///
    /// Use this when no vulnerability data is included in the SBOM
    pub fn without_osv_attribution(
        timestamp: String,
        tool_name: String,
        tool_version: String,
        serial_number: String,
    ) -> Self {
        Self::new(timestamp, tool_name, tool_version, serial_number, None)
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
            None,
        );

        assert_eq!(metadata.timestamp(), "2024-01-01T00:00:00Z");
        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), "0.1.0");
        assert_eq!(metadata.serial_number(), "urn:uuid:12345");
        assert_eq!(metadata.osv_attribution(), None);
    }

    #[test]
    fn test_sbom_metadata_with_osv_attribution() {
        let metadata = SbomMetadata::with_osv_attribution(
            "2024-01-01T00:00:00Z".to_string(),
            "uv-sbom".to_string(),
            "0.1.0".to_string(),
            "urn:uuid:12345".to_string(),
        );

        assert_eq!(metadata.timestamp(), "2024-01-01T00:00:00Z");
        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), "0.1.0");
        assert_eq!(metadata.serial_number(), "urn:uuid:12345");
        assert_eq!(
            metadata.osv_attribution(),
            Some("Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0")
        );
    }

    #[test]
    fn test_sbom_metadata_without_osv_attribution() {
        let metadata = SbomMetadata::without_osv_attribution(
            "2024-01-01T00:00:00Z".to_string(),
            "uv-sbom".to_string(),
            "0.1.0".to_string(),
            "urn:uuid:12345".to_string(),
        );

        assert_eq!(metadata.timestamp(), "2024-01-01T00:00:00Z");
        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), "0.1.0");
        assert_eq!(metadata.serial_number(), "urn:uuid:12345");
        assert_eq!(metadata.osv_attribution(), None);
    }
}
