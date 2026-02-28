//! SBOM read model for query operations
//!
//! This module provides the main read model struct that aggregates
//! all SBOM data in a query-optimized format.

use super::component_view::ComponentView;
use super::dependency_view::DependencyView;
use super::license_compliance_view::LicenseComplianceView;
use super::resolution_guide_view::ResolutionGuideView;
use super::upgrade_recommendation_view::UpgradeRecommendationView;
use super::vulnerability_view::VulnerabilityReportView;

/// Main read model for SBOM data
///
/// This struct provides a denormalized, query-optimized view of SBOM data
/// following the CQRS-lite pattern.
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
    /// License compliance report
    pub license_compliance: Option<LicenseComplianceView>,
    /// Resolution guide for vulnerable transitive dependencies
    #[allow(dead_code)]
    pub resolution_guide: Option<ResolutionGuideView>,
    /// Upgrade recommendations for vulnerable transitive dependencies.
    /// Populated only when `suggest_fix` was true in the request.
    #[allow(dead_code)]
    pub upgrade_recommendations: Option<UpgradeRecommendationView>,
}

/// View representation of SBOM metadata
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
    /// The main project component being analyzed
    pub component: Option<MetadataComponentView>,
}

/// View representation of the main project component in metadata
#[derive(Debug, Clone)]
pub struct MetadataComponentView {
    /// Component name (project name)
    pub name: String,
    /// Component version
    pub version: String,
}
