/// Result of analyzing whether upgrading a direct dep fixes a transitive vulnerability
#[derive(Debug, Clone)]
pub enum UpgradeRecommendation {
    /// Upgrading the direct dep resolves the vulnerability
    Upgradable {
        /// Direct dependency to upgrade (e.g., "requests")
        direct_dep_name: String,
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
        /// Vulnerable transitive dep name (e.g., "idna")
        transitive_dep_name: String,
        /// Version that would fix the vulnerability (e.g., "3.7")
        fixed_version: String,
        /// Why upgrade doesn't help (e.g., "upgrading httpx still resolves idna to 3.6 which does not satisfy >= 3.7")
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
