use crate::application::read_models::SbomReadModel;
use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, Package, SbomMetadata};
use crate::shared::Result;

/// EnrichedPackage represents a package with its license information
///
/// This is used to pass package data with license info to formatters.
#[derive(Debug, Clone)]
pub struct EnrichedPackage {
    pub package: Package,
    pub license: Option<String>,
    pub description: Option<String>,
}

impl EnrichedPackage {
    pub fn new(package: Package, license: Option<String>, description: Option<String>) -> Self {
        Self {
            package,
            license,
            description,
        }
    }
}

/// SbomFormatter port for formatting SBOM output
///
/// This port abstracts the formatting logic for different SBOM formats
/// (CycloneDX JSON, Markdown, etc.).
pub trait SbomFormatter {
    /// Formats packages with metadata into SBOM output
    ///
    /// # Arguments
    /// * `packages` - List of enriched packages with license information
    /// * `metadata` - SBOM metadata (timestamp, tool info, serial number)
    /// * `vulnerability_report` - Optional vulnerability report from CVE check
    ///
    /// # Returns
    /// Formatted SBOM content as a string
    ///
    /// # Errors
    /// Returns an error if formatting or serialization fails
    #[allow(dead_code)]
    fn format(
        &self,
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        vulnerability_report: Option<&[PackageVulnerabilities]>,
    ) -> Result<String>;

    /// Formats packages with dependency graph information
    ///
    /// This method is used for formats that include dependency relationship
    /// information (e.g., Markdown format).
    ///
    /// # Arguments
    /// * `dependency_graph` - Complete dependency graph
    /// * `packages` - List of enriched packages with license information
    /// * `metadata` - SBOM metadata
    /// * `vulnerability_report` - Optional vulnerability report from CVE check
    /// * `vulnerability_result` - Optional threshold-evaluated vulnerability result
    ///
    /// # Returns
    /// Formatted SBOM content as a string
    ///
    /// # Errors
    /// Returns an error if formatting fails
    ///
    /// # Default Implementation
    /// By default, this calls `format()` and ignores the dependency graph.
    /// Formatters that support dependency information should override this.
    #[allow(dead_code)]
    fn format_with_dependencies(
        &self,
        _dependency_graph: &DependencyGraph,
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        vulnerability_report: Option<&[PackageVulnerabilities]>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
    ) -> Result<String> {
        // Default implementation ignores vulnerability_result
        let _ = vulnerability_result;
        self.format(packages, metadata, vulnerability_report)
    }

    /// Formats SBOM output using the unified read model
    ///
    /// This method provides a simplified interface that accepts the pre-built
    /// `SbomReadModel` containing all necessary data for formatting.
    ///
    /// # Arguments
    /// * `model` - The unified SBOM read model containing metadata, components,
    ///   dependencies, and vulnerability information
    ///
    /// # Returns
    /// Formatted SBOM content as a string
    ///
    /// # Errors
    /// Returns an error if formatting or serialization fails
    ///
    /// # Default Implementation
    /// By default, this method is unimplemented and will panic.
    /// Formatters should override this method to provide their implementation.
    fn format_v2(&self, _model: &SbomReadModel) -> Result<String> {
        unimplemented!("format_v2 not yet implemented for this formatter")
    }
}
