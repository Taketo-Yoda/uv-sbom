/// Result of analyzing whether upgrading a direct dep fixes a transitive vulnerability
#[derive(Debug, Clone)]
pub enum UpgradeRecommendation {
    /// Upgrading the direct dep resolves the vulnerability
    Upgradable {
        /// Direct dependency to upgrade (e.g., "requests")
        direct_dep_name: String,
        /// Current version of the direct dependency (e.g., "2.31.0")
        direct_dep_current_version: String,
        /// Recommended version to upgrade to (e.g., "2.32.3")
        direct_dep_target_version: String,
        /// Vulnerable transitive dep name (e.g., "urllib3")
        transitive_dep_name: String,
        /// Version of transitive dep after upgrade (e.g., "2.2.1")
        transitive_resolved_version: String,
        /// Vulnerability ID (e.g., "CVE-2024-XXXXX")
        vulnerability_id: String,
    },
    /// Upgrading the direct dep does NOT resolve the vulnerability
    Unresolvable {
        direct_dep_name: String,
        /// Why upgrade doesn't help (e.g., "latest httpx still pins idna < 3.7")
        reason: String,
        vulnerability_id: String,
    },
    /// Simulation could not be performed (uv not available, timeout, etc.)
    SimulationFailed {
        direct_dep_name: String,
        /// Error description
        error: String,
    },
}
