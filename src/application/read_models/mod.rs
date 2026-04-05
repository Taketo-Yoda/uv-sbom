//! Read models for CQRS-lite pattern
//!
//! This module contains view-optimized structs that provide
//! a denormalized representation of domain data for queries.

pub mod component_view;
pub mod dependency_view;
pub mod license_compliance_view;
pub mod resolution_guide_view;
pub mod sbom_read_model;
pub mod sbom_read_model_builder;
pub mod upgrade_recommendation_view;
pub mod vulnerability_view;

#[allow(unused_imports)]
pub use component_view::{ComponentView, LicenseView};
#[allow(unused_imports)]
pub use dependency_view::DependencyView;
#[allow(unused_imports)]
pub use license_compliance_view::{
    LicenseComplianceSummary, LicenseComplianceView, LicenseViolationView, LicenseWarningView,
};
#[allow(unused_imports)]
pub use resolution_guide_view::{IntroducedByView, ResolutionEntryView, ResolutionGuideView};
#[allow(unused_imports)]
pub use sbom_read_model::{MetadataComponentView, SbomMetadataView, SbomReadModel};
#[allow(unused_imports)]
pub use sbom_read_model_builder::SbomReadModelBuilder;
#[allow(unused_imports)]
pub use upgrade_recommendation_view::{UpgradeEntryView, UpgradeRecommendationView};
#[allow(unused_imports)]
pub use vulnerability_view::{
    SeverityView, VulnerabilityCountsBySeverity, VulnerabilityReportView, VulnerabilitySummary,
    VulnerabilityView,
};
