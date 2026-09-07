use std::collections::HashSet;
use std::path::Path;

use crate::sbom_generation::domain::resolution_guide::ResolutionEntry;
use crate::sbom_generation::domain::services::SimulationOutcomes;
use crate::sbom_generation::domain::UvLockSimulator;

/// Use case that runs `uv lock --upgrade-package` simulations for the unique
/// direct dependencies referenced by a set of `ResolutionEntry` values.
///
/// Produces pre-computed `SimulationOutcomes` for `UpgradeAdvisor` (a pure,
/// synchronous domain service) to compare against OSV fixed versions. This
/// use case owns the only I/O in the upgrade-advice flow; `UpgradeAdvisor`
/// itself performs no I/O.
///
/// # Type Parameters
/// * `S` - `UvLockSimulator` implementation
///
/// Borrows the simulator rather than owning it: `GenerateSbomUseCase`'s
/// `USIM` type parameter has no `Clone` bound (#704), so the injected
/// simulator can only ever be lent out, not cloned into this use case.
pub struct SimulateUpgradesUseCase<'a, S: UvLockSimulator> {
    simulator: &'a S,
}

impl<'a, S: UvLockSimulator> SimulateUpgradesUseCase<'a, S> {
    /// Creates a new `SimulateUpgradesUseCase` borrowing the given simulator.
    pub fn new(simulator: &'a S) -> Self {
        Self { simulator }
    }

    /// Deduplicates direct dependencies referenced across
    /// `resolution_entries` and runs one `simulate_upgrade` per unique name.
    ///
    /// Simulations run sequentially, not concurrently: each `uv lock`
    /// simulation shells out to a subprocess, matching the sequential
    /// execution of the code this use case was extracted from.
    pub async fn run(
        &self,
        resolution_entries: &[ResolutionEntry],
        project_path: &Path,
    ) -> SimulationOutcomes {
        let mut direct_dep_names: HashSet<&str> = HashSet::new();
        for entry in resolution_entries {
            for introduced in entry.introduced_by() {
                direct_dep_names.insert(introduced.package_name());
            }
        }

        let mut simulation_outcomes = SimulationOutcomes::new();
        for direct_dep_name in direct_dep_names {
            let outcome = self
                .simulator
                .simulate_upgrade(direct_dep_name, project_path)
                .await
                .map_err(|e| e.to_string());
            simulation_outcomes.insert(direct_dep_name.to_string(), outcome);
        }

        simulation_outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::MockUvLockSimulator;
    use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
    use crate::sbom_generation::domain::vulnerability::Severity;
    use crate::sbom_generation::domain::SimulationResult;
    use std::path::Path;

    fn make_entry(
        vulnerable: &str,
        current: &str,
        fixed: Option<&str>,
        vuln_id: &str,
        introduced_by: Vec<(&str, &str)>,
    ) -> ResolutionEntry {
        let introduced = introduced_by
            .into_iter()
            .map(|(name, version)| IntroducedBy::new(name.to_string(), version.to_string()))
            .collect();
        ResolutionEntry::new(
            vulnerable.to_string(),
            current.to_string(),
            fixed.map(|v| v.to_string()),
            Severity::High,
            vuln_id.to_string(),
            introduced,
            vec![],
        )
    }

    fn make_sim_result(upgraded_to: &str, resolved: Vec<(&str, &str)>) -> SimulationResult {
        let resolved_versions = resolved
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        SimulationResult {
            upgraded_to_version: upgraded_to.to_string(),
            resolved_versions,
        }
    }

    #[tokio::test]
    async fn test_empty_resolution_entries_produces_empty_outcomes_and_no_calls() {
        let simulator = MockUvLockSimulator::default();
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        let outcomes = use_case.run(&[], Path::new("/project")).await;

        assert!(outcomes.is_empty());
        assert!(simulator.call_log().is_empty());
    }

    #[tokio::test]
    async fn test_single_direct_dep_is_simulated() {
        let simulator = MockUvLockSimulator::with_result(
            "requests",
            make_sim_result("2.32.3", vec![("urllib3", "2.2.1")]),
        );
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0")],
        )];

        let outcomes = use_case.run(&entries, Path::new("/project")).await;

        assert_eq!(outcomes.len(), 1);
        let result = outcomes.get("requests").expect("outcome for requests");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shared_direct_dep_across_entries_is_simulated_once() {
        let simulator = MockUvLockSimulator::with_result(
            "requests",
            make_sim_result(
                "2.32.3",
                vec![("urllib3", "2.2.1"), ("certifi", "2024.1.1")],
            ),
        );
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        // Two entries introduced by the same direct dep "requests".
        let entries = vec![
            make_entry(
                "urllib3",
                "1.26.5",
                Some("2.0.7"),
                "CVE-2024-010",
                vec![("requests", "2.31.0")],
            ),
            make_entry(
                "certifi",
                "2022.9.14",
                Some("2023.7.22"),
                "CVE-2023-100",
                vec![("requests", "2.31.0")],
            ),
        ];

        let outcomes = use_case.run(&entries, Path::new("/project")).await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(simulator.call_log(), vec!["requests".to_string()]);
    }

    #[tokio::test]
    async fn test_multiple_distinct_direct_deps_are_all_simulated() {
        let mut results = std::collections::HashMap::new();
        results.insert(
            "requests".to_string(),
            make_sim_result("2.32.3", vec![("urllib3", "2.2.1")]),
        );
        results.insert(
            "httpx".to_string(),
            make_sim_result("0.28.0", vec![("urllib3", "1.26.15")]),
        );
        let simulator =
            MockUvLockSimulator::with_results_and_errors(results, std::collections::HashMap::new());
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0"), ("httpx", "0.25.0")],
        )];

        let outcomes = use_case.run(&entries, Path::new("/project")).await;

        assert_eq!(outcomes.len(), 2);
        let mut calls = simulator.call_log();
        calls.sort();
        assert_eq!(calls, vec!["httpx".to_string(), "requests".to_string()]);
    }

    #[tokio::test]
    async fn test_simulation_error_is_flattened_to_string() {
        let simulator = MockUvLockSimulator::with_error("requests", "uv command timed out");
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-003",
            vec![("requests", "2.31.0")],
        )];

        let outcomes = use_case.run(&entries, Path::new("/project")).await;

        assert_eq!(outcomes.len(), 1);
        let result = outcomes.get("requests").expect("outcome for requests");
        let error = result.as_ref().expect_err("simulation should have failed");
        assert!(error.contains("timed out"));
    }

    #[tokio::test]
    async fn test_entry_without_fixed_version_still_gets_simulated() {
        // `SimulateUpgradesUseCase` does not filter by `fixed_version` — that
        // filter belongs to `UpgradeAdvisor::advise`, run afterwards. This
        // preserves the pre-refactor `uv lock` call count exactly.
        let simulator = MockUvLockSimulator::with_result(
            "requests",
            make_sim_result("2.32.3", vec![("urllib3", "2.2.1")]),
        );
        let use_case = SimulateUpgradesUseCase::new(&simulator);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            None, // No known fix
            "CVE-2024-004",
            vec![("requests", "2.31.0")],
        )];

        let outcomes = use_case.run(&entries, Path::new("/project")).await;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(simulator.call_log(), vec!["requests".to_string()]);
    }
}
