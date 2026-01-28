//! SBOM read model for query operations
//!
//! This module provides the main read model struct that aggregates
//! all SBOM data in a query-optimized format.

use super::component_view::ComponentView;
use super::dependency_view::DependencyView;
use super::vulnerability_view::VulnerabilityReportView;

/// Main read model for SBOM data
///
/// This struct provides a denormalized, query-optimized view of SBOM data
/// following the CQRS-lite pattern.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SbomReadModel {
    /// SBOM metadata
    pub metadata: SbomMetadataView,
    /// List of components
    pub components: Vec<ComponentView>,
    /// Dependency information
    pub dependencies: Option<DependencyView>,
    /// Vulnerability report
    pub vulnerabilities: Option<VulnerabilityReportView>,
}

/// View representation of SBOM metadata
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SbomMetadataView {
    /// Timestamp when the SBOM was created
    pub timestamp: String,
    /// Name of the tool that generated the SBOM
    pub tool_name: String,
    /// Version of the tool
    pub tool_version: String,
    /// Serial number of the SBOM
    pub serial_number: String,
}
