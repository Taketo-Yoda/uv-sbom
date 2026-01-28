//! Read models for CQRS-lite pattern
//!
//! This module contains view-optimized structs that provide
//! a denormalized representation of domain data for queries.

pub mod component_view;
pub mod sbom_read_model;

#[allow(unused_imports)]
pub use component_view::{ComponentView, LicenseView};
#[allow(unused_imports)]
pub use sbom_read_model::{
    DependencyView, SbomMetadataView, SbomReadModel, VulnerabilityReportView,
};
