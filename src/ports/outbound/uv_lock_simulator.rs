use anyhow::Result;
use std::collections::HashMap;

/// Represents the result of a `uv lock --upgrade-package` simulation
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// The version it was upgraded to
    pub upgraded_to_version: String,
    /// Map of transitive package name → resolved version after upgrade
    pub resolved_versions: HashMap<String, String>,
}

/// Port for simulating dependency resolution with package upgrades
#[async_trait::async_trait]
pub trait UvLockSimulator: Send + Sync {
    /// Simulate upgrading a specific package and return the resolved dependency versions.
    ///
    /// Runs `uv lock --upgrade-package <package_name>` (or equivalent) and parses
    /// the resulting lock file to determine what versions would be resolved.
    ///
    /// # Arguments
    /// * `package_name` - The direct dependency to upgrade
    /// * `project_path` - Path to the project directory containing pyproject.toml
    async fn simulate_upgrade(
        &self,
        package_name: &str,
        project_path: &std::path::Path,
    ) -> Result<SimulationResult>;
}
