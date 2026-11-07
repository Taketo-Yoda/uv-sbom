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

/// Outcome of a version-targeted `uv lock --upgrade-package <name>==<version>`
/// simulation (#966).
///
/// The three variants are the outcomes incident mode branches on when deciding
/// whether a suggested upgrade command is verified. Infrastructure failures
/// (missing project files, temp-dir I/O, timeout) are reported as `Err` by the
/// trait method instead, matching `simulate_upgrade`'s error contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetedSimulationOutcome {
    /// The lock resolved, with the package at the target version or newer.
    Resolved { resolved_version: String },
    /// `uv` could not resolve the request (e.g. a conflicting constraint), or
    /// the resolved lock lacks the package or holds a version older than the
    /// target. `reason` carries uv's stderr summary or a description.
    ResolutionFailed { reason: String },
    /// The `uv` CLI is not runnable (not found on PATH).
    SimulatorUnavailable,
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

    /// Simulate upgrading a package to a specific target version.
    ///
    /// Runs `uv lock --upgrade-package <package_name>==<target_version>` (or
    /// equivalent) against a copy of the project, so the original `uv.lock` is
    /// never modified. Succeeds when the resolved lock contains the package at
    /// `target_version` or newer.
    ///
    /// # Arguments
    /// * `package_name` - The package to upgrade (untrusted; validated by implementors)
    /// * `target_version` - The PEP 440 version to upgrade to (untrusted)
    /// * `project_path` - Path to the project directory containing pyproject.toml
    ///
    /// # Returns
    /// `Ok` with one of the three [`TargetedSimulationOutcome`] variants: the
    /// resolved version when it is at or above `target_version`,
    /// `ResolutionFailed` when uv rejects the request or the resolved lock does
    /// not satisfy the target, or `SimulatorUnavailable` when `uv` is not runnable.
    ///
    /// # Errors
    /// Returns `Err` when `package_name` or `target_version` is rejected as
    /// unsafe input (the message starts with `Security:`), when `pyproject.toml`
    /// or `uv.lock` is missing from `project_path`, when the sandbox copy or the
    /// resulting lock cannot be read or parsed, or when uv times out or cannot
    /// be spawned.
    async fn simulate_upgrade_to(
        &self,
        package_name: &str,
        target_version: &str,
        project_path: &std::path::Path,
    ) -> Result<TargetedSimulationOutcome>;
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

    async fn simulate_upgrade_to(
        &self,
        _package_name: &str,
        _target_version: &str,
        _project_path: &std::path::Path,
    ) -> Result<TargetedSimulationOutcome> {
        unreachable!("UvLockSimulator not configured")
    }
}
