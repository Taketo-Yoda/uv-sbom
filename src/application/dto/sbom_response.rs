use crate::ports::outbound::EnrichedPackage;
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
}

impl SbomResponse {
    pub fn new(
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<DependencyGraph>,
        metadata: SbomMetadata,
    ) -> Self {
        Self {
            enriched_packages,
            dependency_graph,
            metadata,
        }
    }
}
