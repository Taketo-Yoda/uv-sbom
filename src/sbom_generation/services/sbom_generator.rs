use crate::sbom_generation::domain::SbomMetadata;
use chrono::Utc;
use uuid::Uuid;

/// SbomGenerator service for generating SBOM metadata
///
/// This service contains pure business logic for SBOM metadata generation.
/// It creates metadata conforming to CycloneDX specification.
pub struct SbomGenerator;

impl SbomGenerator {
    /// Generates SBOM metadata with current timestamp and unique serial number
    ///
    /// # Arguments
    /// * `tool_name` - Name of the tool generating the SBOM
    /// * `tool_version` - Version of the tool
    /// * `include_osv_attribution` - Whether to include OSV attribution for CC-BY 4.0 compliance
    ///
    /// # Returns
    /// SbomMetadata with generated timestamp and UUID serial number
    pub fn generate_metadata(
        tool_name: &str,
        tool_version: &str,
        include_osv_attribution: bool,
    ) -> SbomMetadata {
        let timestamp = Utc::now().to_rfc3339();
        let serial_number = format!("urn:uuid:{}", Uuid::new_v4());

        if include_osv_attribution {
            SbomMetadata::with_osv_attribution(
                timestamp,
                tool_name.to_string(),
                tool_version.to_string(),
                serial_number,
            )
        } else {
            SbomMetadata::without_osv_attribution(
                timestamp,
                tool_name.to_string(),
                tool_version.to_string(),
                serial_number,
            )
        }
    }

    /// Generates SBOM metadata with default tool information (uv-sbom)
    ///
    /// This uses the compile-time version from Cargo.toml
    ///
    /// # Arguments
    /// * `include_osv_attribution` - Whether to include OSV attribution for CC-BY 4.0 compliance
    pub fn generate_default_metadata(include_osv_attribution: bool) -> SbomMetadata {
        Self::generate_metadata(
            "uv-sbom",
            env!("CARGO_PKG_VERSION"),
            include_osv_attribution,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_metadata() {
        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);

        assert_eq!(metadata.tool_name(), "test-tool");
        assert_eq!(metadata.tool_version(), "1.0.0");
        assert!(metadata.serial_number().starts_with("urn:uuid:"));
        assert!(!metadata.timestamp().is_empty());
        assert_eq!(metadata.osv_attribution(), None);
    }

    #[test]
    fn test_generate_metadata_with_osv_attribution() {
        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", true);

        assert_eq!(metadata.tool_name(), "test-tool");
        assert_eq!(metadata.tool_version(), "1.0.0");
        assert!(metadata.serial_number().starts_with("urn:uuid:"));
        assert!(!metadata.timestamp().is_empty());
        assert_eq!(
            metadata.osv_attribution(),
            Some("Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0")
        );
    }

    #[test]
    fn test_generate_default_metadata() {
        let metadata = SbomGenerator::generate_default_metadata(false);

        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), env!("CARGO_PKG_VERSION"));
        assert!(metadata.serial_number().starts_with("urn:uuid:"));
        assert_eq!(metadata.osv_attribution(), None);
    }

    #[test]
    fn test_generate_default_metadata_with_osv_attribution() {
        let metadata = SbomGenerator::generate_default_metadata(true);

        assert_eq!(metadata.tool_name(), "uv-sbom");
        assert_eq!(metadata.tool_version(), env!("CARGO_PKG_VERSION"));
        assert!(metadata.serial_number().starts_with("urn:uuid:"));
        assert_eq!(
            metadata.osv_attribution(),
            Some("Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0")
        );
    }

    #[test]
    fn test_generate_metadata_timestamp_format() {
        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let timestamp = metadata.timestamp();

        // RFC3339 format should contain 'T' and timezone info
        assert!(timestamp.contains('T'));
        assert!(timestamp.contains('+') || timestamp.contains('Z'));
    }

    #[test]
    fn test_generate_metadata_unique_serial_numbers() {
        let metadata1 = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let metadata2 = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);

        // Each generation should create a unique UUID
        assert_ne!(metadata1.serial_number(), metadata2.serial_number());
    }

    #[test]
    fn test_generate_metadata_uuid_format() {
        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let serial = metadata.serial_number();

        // Verify UUID format: urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert!(serial.starts_with("urn:uuid:"));
        let uuid_part = serial.strip_prefix("urn:uuid:").unwrap();
        assert_eq!(uuid_part.len(), 36); // UUID v4 length with hyphens
        assert_eq!(uuid_part.matches('-').count(), 4);
    }
}
