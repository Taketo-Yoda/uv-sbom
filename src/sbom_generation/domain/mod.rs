pub mod dependency_graph;
pub mod license_info;
pub mod package;
pub mod sbom_metadata;
pub mod vulnerability;

pub use dependency_graph::DependencyGraph;
pub use license_info::LicenseInfo;
pub use package::{Package, PackageName};
pub use sbom_metadata::SbomMetadata;
// Note: These will be used in subsequent subtasks (Subtask 2-8)
#[allow(unused_imports)]
pub use vulnerability::{PackageVulnerabilities, Severity, Vulnerability};
