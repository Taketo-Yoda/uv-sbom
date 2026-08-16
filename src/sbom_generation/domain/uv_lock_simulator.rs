//! Domain-owned port for uv lock simulation.
//!
//! This trait was moved into the domain layer in #703 because `UpgradeAdvisor`
//! (a domain service) consumed it directly as a generic bound. As of #716,
//! `UpgradeAdvisor` is a pure, synchronous comparator that no longer touches
//! this trait at all — the simulation-running loop now lives in
//! `application::use_cases::SimulateUpgradesUseCase`, which owns this port the
//! same way other application-layer use cases own their outbound ports. The
//! trait itself remains here for now rather than moving to
//! `src/ports/outbound/`; `SimulationResult` is a plain value object (no I/O)
//! so it can stay regardless. It is implemented by
//! `adapters::outbound::uv::UvLockAdapter`.

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

/// Null-object impl so `GenerateSbomUseCase`'s `USIM = ()` default satisfies the
/// trait bound. Never called in practice: the use case only reaches the
/// simulator through `Option<USIM>`, which the CLI composition root always
/// populates with a real `UvLockAdapter`; `None`/`()` only arises in tests that
/// intentionally omit a simulator. Mirrors `impl PythonCompatibilityRepository
/// for ()` in `src/ports/outbound/python_compatibility_repository.rs`.
#[async_trait::async_trait]
impl UvLockSimulator for () {
    async fn simulate_upgrade(
        &self,
        _package_name: &str,
        _project_path: &std::path::Path,
    ) -> Result<SimulationResult> {
        unreachable!("UvLockSimulator not configured")
    }
}
