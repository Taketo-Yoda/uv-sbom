use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};

/// SbomResponse - Internal response DTO from SBOM generation use case
///
/// This DTO contains the rich data structures produced by the use case,
/// which adapters can then format into the appropriate output format.
#[derive(Debug, Clone)]
pub struct SbomResponse {
    /// Packages enriched with license information
    pub enriched_packages: Vec<EnrichedPackage>,
    /// Optional dependency graph (only present when requested)
    pub dependency_graph: Option<DependencyGraph>,
    /// SBOM metadata (timestamp, tool info, serial number)
    pub metadata: SbomMetadata,
    /// Optional vulnerability report (only present when CVE check is enabled)
    /// None = not checked, Some(vec) = checked (empty vec means no vulnerabilities found)
    #[allow(dead_code)] // Will be used in subsequent subtasks
    pub vulnerability_report: Option<Vec<PackageVulnerabilities>>,
}

impl SbomResponse {
    pub fn new(
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<DependencyGraph>,
        metadata: SbomMetadata,
        vulnerability_report: Option<Vec<PackageVulnerabilities>>,
    ) -> Self {
        Self {
            enriched_packages,
            dependency_graph,
            metadata,
            vulnerability_report,
        }
    }
}
