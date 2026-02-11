pub mod dependency_graph;
pub mod license_info;
pub mod license_policy;
pub mod package;
pub mod resolution_guide;
pub mod sbom_metadata;
pub mod services;
pub mod vulnerability;

pub use dependency_graph::DependencyGraph;
pub use license_info::LicenseInfo;
// Note: These types are used within the application layer via full paths
#[allow(unused_imports)]
pub use license_policy::{
    LicenseComplianceResult, LicensePolicy, LicenseViolation, LicenseWarning,
    UnknownLicenseHandling, ViolationReason,
};
pub use package::{Package, PackageName};
// Note: These will be used in subsequent subtasks (Issue #221 sub-tasks 2-4)
#[allow(unused_imports)]
pub use resolution_guide::{IntroducedBy, ResolutionEntry};
pub use sbom_metadata::SbomMetadata;
// Note: These will be used in subsequent subtasks (Issue #94, #95)
#[allow(unused_imports)]
pub use services::{ThresholdConfig, VulnerabilityCheckResult, VulnerabilityChecker};
// Note: These will be used in subsequent subtasks (Subtask 2-8)
#[allow(unused_imports)]
pub use vulnerability::{CvssScore, PackageVulnerabilities, Severity, Vulnerability};
