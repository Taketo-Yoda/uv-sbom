pub mod cve_filter;
pub mod dependency_diff_analyzer;
pub mod dependency_tree_builder;
pub mod group_reachability_analyzer;
pub mod license_compliance_checker;
pub mod python_compatibility_checker;
pub mod resolution_analyzer;
pub mod upgrade_advisor;
pub mod vulnerability_checker;

#[allow(unused_imports)]
pub use dependency_diff_analyzer::DependencyDiffAnalyzer;
// Note: Will be consumed by the application layer in Issue #781
#[allow(unused_imports)]
pub use dependency_tree_builder::{DependencyTreeBuilder, TreeNode};
pub use group_reachability_analyzer::GroupReachabilityAnalyzer;
pub use license_compliance_checker::LicenseComplianceChecker;
pub use python_compatibility_checker::PythonCompatibilityChecker;
pub use resolution_analyzer::ResolutionAnalyzer;
pub use upgrade_advisor::{SimulationOutcomes, UpgradeAdvisor};
pub use vulnerability_checker::{ThresholdConfig, VulnerabilityCheckResult, VulnerabilityChecker};
