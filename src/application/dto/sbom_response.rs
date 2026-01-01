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

    /// Creates a response without dependency graph information
    pub fn without_dependencies(enriched_packages: Vec<EnrichedPackage>, metadata: SbomMetadata) -> Self {
        Self::new(enriched_packages, None, metadata)
    }

    /// Creates a response with dependency graph information
    pub fn with_dependencies(
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: DependencyGraph,
        metadata: SbomMetadata,
    ) -> Self {
        Self::new(enriched_packages, Some(dependency_graph), metadata)
    }
}
