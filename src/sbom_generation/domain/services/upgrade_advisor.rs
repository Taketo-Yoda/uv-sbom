use std::collections::HashMap;

use crate::ports::outbound::uv_lock_simulator::{SimulationResult, UvLockSimulator};
use crate::sbom_generation::domain::resolution_guide::ResolutionEntry;
use crate::sbom_generation::domain::upgrade_recommendation::UpgradeRecommendation;

/// Stateless domain service that orchestrates upgrade simulations and produces
/// `UpgradeRecommendation` results by comparing resolved transitive versions
/// against OSV fixed versions.
#[allow(dead_code)]
pub struct UpgradeAdvisor;

impl UpgradeAdvisor {
    /// For each ResolutionEntry, simulate upgrading the introducing direct dependency
    /// and check if the transitive vulnerability is resolved.
    ///
    /// # Algorithm
    /// 1. Group ResolutionEntries by direct_dep_name to deduplicate simulations
    /// 2. For each unique direct dep, call `simulator.simulate_upgrade()`
    /// 3. For each vulnerable transitive dep introduced by that direct dep:
    ///    a. Look up resolved version in SimulationResult
    ///    b. Compare with fixed_version from OSV using PEP 440 comparison
    ///    c. resolved >= fixed → Upgradable
    ///    d. resolved < fixed → Unresolvable
    /// 4. On simulation error → SimulationFailed
    #[allow(dead_code)]
    pub async fn advise<S: UvLockSimulator>(
        simulator: &S,
        resolution_entries: &[ResolutionEntry],
        project_path: &std::path::Path,
    ) -> Vec<UpgradeRecommendation> {
        // Collect unique direct deps and their current versions
        let mut direct_dep_versions: HashMap<String, String> = HashMap::new();
        for entry in resolution_entries {
            for introduced in entry.introduced_by() {
                direct_dep_versions
                    .entry(introduced.package_name().to_string())
                    .or_insert_with(|| introduced.version().to_string());
            }
        }

        // Run deduplicated simulations for each unique direct dep
        let mut simulation_outcomes: HashMap<String, Result<SimulationResult, String>> =
            HashMap::new();
        for direct_dep_name in direct_dep_versions.keys() {
            let outcome = simulator
                .simulate_upgrade(direct_dep_name, project_path)
                .await
                .map_err(|e| e.to_string());
            simulation_outcomes.insert(direct_dep_name.clone(), outcome);
        }

        // Build recommendations for each (entry, introduced_by) pair
        let mut recommendations = Vec::new();
        for entry in resolution_entries {
            let fixed_version = match entry.fixed_version() {
                Some(v) => v,
                None => continue, // No fix known — skip
            };
            let fixed_version_normalized = strip_operator_prefix(fixed_version);

            for introduced in entry.introduced_by() {
                let direct_dep_name = introduced.package_name().to_string();
                let direct_dep_current_version = introduced.version().to_string();

                match simulation_outcomes.get(&direct_dep_name) {
                    Some(Ok(sim_result)) => {
                        if let Some(resolved_version) =
                            sim_result.resolved_versions.get(entry.vulnerable_package())
                        {
                            if version_satisfies_min(resolved_version, &fixed_version_normalized) {
                                recommendations.push(UpgradeRecommendation::Upgradable {
                                    direct_dep_name,
                                    direct_dep_current_version,
                                    direct_dep_target_version: sim_result
                                        .upgraded_to_version
                                        .clone(),
                                    transitive_dep_name: entry.vulnerable_package().to_string(),
                                    transitive_resolved_version: resolved_version.clone(),
                                    vulnerability_id: entry.vulnerability_id().to_string(),
                                });
                            } else {
                                recommendations.push(UpgradeRecommendation::Unresolvable {
                                    direct_dep_name: direct_dep_name.clone(),
                                    reason: format!(
                                        "upgrading {} still resolves {} to {} which does not satisfy >= {}",
                                        direct_dep_name,
                                        entry.vulnerable_package(),
                                        resolved_version,
                                        fixed_version_normalized
                                    ),
                                    vulnerability_id: entry.vulnerability_id().to_string(),
                                });
                            }
                        } else {
                            // Vulnerable package removed after upgrade — treat as resolved
                            recommendations.push(UpgradeRecommendation::Upgradable {
                                direct_dep_name,
                                direct_dep_current_version,
                                direct_dep_target_version: sim_result.upgraded_to_version.clone(),
                                transitive_dep_name: entry.vulnerable_package().to_string(),
                                transitive_resolved_version: String::new(),
                                vulnerability_id: entry.vulnerability_id().to_string(),
                            });
                        }
                    }
                    Some(Err(e)) => {
                        recommendations.push(UpgradeRecommendation::SimulationFailed {
                            direct_dep_name,
                            error: e.clone(),
                        });
                    }
                    None => {}
                }
            }
        }

        recommendations
    }
}

/// Strip operator prefix from version strings (e.g., `">= 2.0.7"` → `"2.0.7"`).
fn strip_operator_prefix(version: &str) -> String {
    version
        .trim()
        .trim_start_matches(['>', '<', '=', '!'])
        .trim()
        .to_string()
}

/// Compare two PEP 440 version strings.
/// Returns true if `actual` satisfies `required_min` (i.e., actual >= required_min).
/// Uses simple dot-separated numeric comparison for common cases.
/// Pre-release markers in `actual` cause a conservative false return.
fn version_satisfies_min(actual: &str, required_min: &str) -> bool {
    let actual_parts = parse_version_parts(actual);
    let min_parts = parse_version_parts(required_min);

    if actual_parts.is_empty() {
        return false;
    }

    let max_len = actual_parts.len().max(min_parts.len());
    for i in 0..max_len {
        let a = actual_parts.get(i).copied().unwrap_or(0);
        let m = min_parts.get(i).copied().unwrap_or(0);
        match a.cmp(&m) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true // versions are equal → satisfies minimum
}

/// Parse a version string into its numeric components.
/// Stops at the first non-numeric character within each dot-separated segment.
/// For example, `"1.0.0rc1"` → `[1, 0, 0]`.
fn parse_version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .filter_map(|segment| {
            let numeric: String = segment.chars().take_while(|c| c.is_ascii_digit()).collect();
            if numeric.is_empty() {
                None
            } else {
                numeric.parse().ok()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
    use crate::sbom_generation::domain::vulnerability::Severity;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::Path;

    // ---------------------------------------------------------------------------
    // Mock simulator
    // ---------------------------------------------------------------------------

    struct MockSimulator {
        results: HashMap<String, SimulationResult>,
        errors: HashMap<String, String>,
    }

    impl MockSimulator {
        fn with_result(package: &str, result: SimulationResult) -> Self {
            let mut results = HashMap::new();
            results.insert(package.to_string(), result);
            Self {
                results,
                errors: HashMap::new(),
            }
        }

        fn with_error(package: &str, error: &str) -> Self {
            let mut errors = HashMap::new();
            errors.insert(package.to_string(), error.to_string());
            Self {
                results: HashMap::new(),
                errors,
            }
        }

        fn with_results_and_errors(
            results: HashMap<String, SimulationResult>,
            errors: HashMap<String, String>,
        ) -> Self {
            Self { results, errors }
        }
    }

    #[async_trait]
    impl UvLockSimulator for MockSimulator {
        async fn simulate_upgrade(
            &self,
            package_name: &str,
            _project_path: &Path,
        ) -> Result<SimulationResult> {
            if let Some(error) = self.errors.get(package_name) {
                return Err(anyhow::anyhow!("{}", error));
            }
            if let Some(result) = self.results.get(package_name) {
                return Ok(result.clone());
            }
            Err(anyhow::anyhow!(
                "package not configured in mock: {}",
                package_name
            ))
        }
    }

    // ---------------------------------------------------------------------------
    // Helper builders
    // ---------------------------------------------------------------------------

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
        )
    }

    fn make_sim_result(
        upgraded_package: &str,
        upgraded_to: &str,
        resolved: Vec<(&str, &str)>,
    ) -> SimulationResult {
        let resolved_versions = resolved
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        SimulationResult {
            upgraded_package: upgraded_package.to_string(),
            upgraded_to_version: upgraded_to.to_string(),
            resolved_versions,
        }
    }

    // ---------------------------------------------------------------------------
    // UpgradeAdvisor::advise tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_upgradable_when_resolved_version_satisfies_fixed() {
        let sim_result = make_sim_result("requests", "2.32.3", vec![("urllib3", "2.2.1")]);
        let simulator = MockSimulator::with_result("requests", sim_result);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert_eq!(recommendations.len(), 1);
        match &recommendations[0] {
            UpgradeRecommendation::Upgradable {
                direct_dep_name,
                direct_dep_target_version,
                transitive_dep_name,
                transitive_resolved_version,
                vulnerability_id,
                ..
            } => {
                assert_eq!(direct_dep_name, "requests");
                assert_eq!(direct_dep_target_version, "2.32.3");
                assert_eq!(transitive_dep_name, "urllib3");
                assert_eq!(transitive_resolved_version, "2.2.1");
                assert_eq!(vulnerability_id, "CVE-2024-001");
            }
            other => panic!("expected Upgradable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_unresolvable_when_resolved_version_below_fixed() {
        let sim_result = make_sim_result("httpx", "0.28.0", vec![("idna", "3.6")]);
        let simulator = MockSimulator::with_result("httpx", sim_result);

        let entries = vec![make_entry(
            "idna",
            "3.3",
            Some("3.7"),
            "CVE-2024-002",
            vec![("httpx", "0.25.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert_eq!(recommendations.len(), 1);
        match &recommendations[0] {
            UpgradeRecommendation::Unresolvable {
                direct_dep_name,
                vulnerability_id,
                ..
            } => {
                assert_eq!(direct_dep_name, "httpx");
                assert_eq!(vulnerability_id, "CVE-2024-002");
            }
            other => panic!("expected Unresolvable, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_simulation_failed_on_error() {
        let simulator = MockSimulator::with_error("requests", "uv command timed out");

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-003",
            vec![("requests", "2.31.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert_eq!(recommendations.len(), 1);
        match &recommendations[0] {
            UpgradeRecommendation::SimulationFailed {
                direct_dep_name,
                error,
            } => {
                assert_eq!(direct_dep_name, "requests");
                assert!(error.contains("timed out"));
            }
            other => panic!("expected SimulationFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_entry_without_fixed_version_is_skipped() {
        let sim_result = make_sim_result("requests", "2.32.3", vec![("urllib3", "2.2.1")]);
        let simulator = MockSimulator::with_result("requests", sim_result);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            None, // No known fix
            "CVE-2024-004",
            vec![("requests", "2.31.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert!(recommendations.is_empty());
    }

    #[tokio::test]
    async fn test_simulations_are_deduplicated_for_multiple_entries() {
        // Two ResolutionEntries share the same direct dep "requests"
        let sim_result = make_sim_result(
            "requests",
            "2.32.3",
            vec![("urllib3", "2.2.1"), ("certifi", "2024.1.1")],
        );
        let simulator = MockSimulator::with_result("requests", sim_result);

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

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        // Both should be Upgradable; simulate_upgrade called only once for "requests"
        assert_eq!(recommendations.len(), 2);
        assert!(recommendations
            .iter()
            .all(|r| matches!(r, UpgradeRecommendation::Upgradable { .. })));
    }

    #[tokio::test]
    async fn test_multiple_direct_deps_produce_separate_recommendations() {
        let mut results = HashMap::new();
        results.insert(
            "requests".to_string(),
            make_sim_result("requests", "2.32.3", vec![("urllib3", "2.2.1")]),
        );
        results.insert(
            "httpx".to_string(),
            make_sim_result("httpx", "0.28.0", vec![("urllib3", "1.26.15")]),
        );

        let simulator = MockSimulator::with_results_and_errors(results, HashMap::new());

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0"), ("httpx", "0.25.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert_eq!(recommendations.len(), 2);
        let upgradable_count = recommendations
            .iter()
            .filter(|r| matches!(r, UpgradeRecommendation::Upgradable { .. }))
            .count();
        let unresolvable_count = recommendations
            .iter()
            .filter(|r| matches!(r, UpgradeRecommendation::Unresolvable { .. }))
            .count();
        assert_eq!(upgradable_count, 1); // requests → urllib3 2.2.1 >= 2.0.7
        assert_eq!(unresolvable_count, 1); // httpx → urllib3 1.26.15 < 2.0.7
    }

    #[tokio::test]
    async fn test_operator_prefixed_fixed_version_is_stripped() {
        let sim_result = make_sim_result("requests", "2.32.3", vec![("urllib3", "2.2.1")]);
        let simulator = MockSimulator::with_result("requests", sim_result);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some(">= 2.0.7"), // OSV-style operator prefix
            "CVE-2024-005",
            vec![("requests", "2.31.0")],
        )];

        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, Path::new("/project")).await;

        assert_eq!(recommendations.len(), 1);
        assert!(matches!(
            recommendations[0],
            UpgradeRecommendation::Upgradable { .. }
        ));
    }

    // ---------------------------------------------------------------------------
    // version_satisfies_min unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_version_satisfies_min_greater() {
        assert!(version_satisfies_min("2.2.1", "2.0.7"));
    }

    #[test]
    fn test_version_satisfies_min_equal() {
        assert!(version_satisfies_min("2.0.7", "2.0.7"));
    }

    #[test]
    fn test_version_satisfies_min_less() {
        assert!(!version_satisfies_min("1.26.15", "2.0.7"));
    }

    #[test]
    fn test_version_satisfies_min_patch_less() {
        assert!(!version_satisfies_min("2.0.6", "2.0.7"));
    }

    #[test]
    fn test_version_satisfies_min_patch_greater() {
        assert!(version_satisfies_min("2.0.8", "2.0.7"));
    }

    #[test]
    fn test_version_satisfies_min_empty_actual() {
        assert!(!version_satisfies_min("", "2.0.7"));
    }

    // ---------------------------------------------------------------------------
    // strip_operator_prefix unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_strip_prefix_gte() {
        assert_eq!(strip_operator_prefix(">= 2.0.7"), "2.0.7");
    }

    #[test]
    fn test_strip_prefix_gt() {
        assert_eq!(strip_operator_prefix("> 2.0.7"), "2.0.7");
    }

    #[test]
    fn test_strip_prefix_no_operator() {
        assert_eq!(strip_operator_prefix("2.0.7"), "2.0.7");
    }
}
