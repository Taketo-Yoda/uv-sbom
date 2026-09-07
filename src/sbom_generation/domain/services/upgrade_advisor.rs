use std::collections::HashMap;
use std::str::FromStr;

use pep440_rs::Version;

use crate::sbom_generation::domain::resolution_guide::ResolutionEntry;
use crate::sbom_generation::domain::upgrade_recommendation::UpgradeRecommendation;
use crate::sbom_generation::domain::SimulationResult;

/// Pre-computed simulation outcomes keyed by direct dependency name.
///
/// The error variant is flattened to `String` rather than the port's
/// `anyhow::Error` because the domain layer must not depend on the port's
/// error type; `SimulateUpgradesUseCase` (application layer) is responsible
/// for running the simulations and building this map.
pub type SimulationOutcomes = HashMap<String, Result<SimulationResult, String>>;

/// Stateless domain service that compares pre-computed upgrade simulation
/// outcomes against OSV fixed versions to produce `UpgradeRecommendation`s.
pub struct UpgradeAdvisor;

impl UpgradeAdvisor {
    /// For each ResolutionEntry, look up the simulation outcome for the
    /// introducing direct dependency and check if the transitive
    /// vulnerability is resolved.
    ///
    /// # Algorithm
    /// For each vulnerable transitive dep introduced by a direct dep:
    /// 1. Look up the pre-computed outcome in `simulation_outcomes`
    /// 2. On `Ok`, compare the resolved version with `fixed_version` from OSV
    ///    using PEP 440 comparison — resolved >= fixed → Upgradable,
    ///    resolved < fixed → Unresolvable
    /// 3. On `Err` → SimulationFailed
    /// 4. Missing entry (simulation was never run for that dependency) → skipped
    pub fn advise(
        resolution_entries: &[ResolutionEntry],
        simulation_outcomes: &SimulationOutcomes,
    ) -> Vec<UpgradeRecommendation> {
        let mut recommendations = Vec::new();
        for entry in resolution_entries {
            let fixed_version = match entry.fixed_version() {
                Some(v) => v,
                None => continue, // No fix known — skip
            };
            let fixed_version_normalized = strip_operator_prefix(fixed_version);

            for introduced in entry.introduced_by() {
                let direct_dep_name = introduced.package_name().to_string();

                match simulation_outcomes.get(&direct_dep_name) {
                    Some(Ok(sim_result)) => {
                        if let Some(resolved_version) =
                            sim_result.resolved_versions.get(entry.vulnerable_package())
                        {
                            if version_satisfies_min(resolved_version, &fixed_version_normalized) {
                                recommendations.push(UpgradeRecommendation::Upgradable {
                                    direct_dep_name,
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
///
/// `pep440_rs::Version::from_str` only accepts a bare version string, not a
/// specifier, so OSV-style fixed-version strings (which may carry an operator
/// prefix) must be normalized with this function before parsing.
fn strip_operator_prefix(version: &str) -> String {
    version
        .trim()
        .trim_start_matches(['>', '<', '=', '!'])
        .trim()
        .to_string()
}

/// Compare two PEP 440 version strings using `pep440_rs::Version`.
/// Returns true if `actual` satisfies `required_min` (i.e., actual >= required_min).
///
/// If either string fails to parse as a valid PEP 440 version, this returns
/// `false` as a conservative fallback.
fn version_satisfies_min(actual: &str, required_min: &str) -> bool {
    let (Ok(actual_v), Ok(min_v)) = (Version::from_str(actual), Version::from_str(required_min))
    else {
        return false;
    };
    actual_v >= min_v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
    use crate::sbom_generation::domain::vulnerability::Severity;

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

    fn outcomes(pairs: Vec<(&str, Result<SimulationResult, &str>)>) -> SimulationOutcomes {
        pairs
            .into_iter()
            .map(|(name, outcome)| (name.to_string(), outcome.map_err(|e| e.to_string())))
            .collect()
    }

    // ---------------------------------------------------------------------------
    // UpgradeAdvisor::advise tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_upgradable_when_resolved_version_satisfies_fixed() {
        let sim_outcomes = outcomes(vec![(
            "requests",
            Ok(make_sim_result("2.32.3", vec![("urllib3", "2.2.1")])),
        )]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

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

    #[test]
    fn test_unresolvable_when_resolved_version_below_fixed() {
        let sim_outcomes = outcomes(vec![(
            "httpx",
            Ok(make_sim_result("0.28.0", vec![("idna", "3.6")])),
        )]);

        let entries = vec![make_entry(
            "idna",
            "3.3",
            Some("3.7"),
            "CVE-2024-002",
            vec![("httpx", "0.25.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

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

    #[test]
    fn test_simulation_failed_on_error() {
        let sim_outcomes = outcomes(vec![("requests", Err("uv command timed out"))]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-003",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

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

    #[test]
    fn test_entry_without_fixed_version_is_skipped() {
        let sim_outcomes = outcomes(vec![(
            "requests",
            Ok(make_sim_result("2.32.3", vec![("urllib3", "2.2.1")])),
        )]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            None, // No known fix
            "CVE-2024-004",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_shared_outcome_produces_recommendation_for_each_entry() {
        // Two ResolutionEntries share the same direct dep "requests" outcome
        let sim_outcomes = outcomes(vec![(
            "requests",
            Ok(make_sim_result(
                "2.32.3",
                vec![("urllib3", "2.2.1"), ("certifi", "2024.1.1")],
            )),
        )]);

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

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

        assert_eq!(recommendations.len(), 2);
        assert!(recommendations
            .iter()
            .all(|r| matches!(r, UpgradeRecommendation::Upgradable { .. })));
    }

    #[test]
    fn test_multiple_direct_deps_produce_separate_recommendations() {
        let sim_outcomes = outcomes(vec![
            (
                "requests",
                Ok(make_sim_result("2.32.3", vec![("urllib3", "2.2.1")])),
            ),
            (
                "httpx",
                Ok(make_sim_result("0.28.0", vec![("urllib3", "1.26.15")])),
            ),
        ]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-001",
            vec![("requests", "2.31.0"), ("httpx", "0.25.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

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

    #[test]
    fn test_empty_resolution_entries_returns_empty_vec() {
        let sim_outcomes = outcomes(vec![("any-package", Err("should not be looked up"))]);
        let recommendations = UpgradeAdvisor::advise(&[], &sim_outcomes);
        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_missing_outcome_for_direct_dep_is_skipped() {
        // No entry in `simulation_outcomes` for "requests" — e.g. because the
        // caller never ran a simulation for it. Must not panic; the entry is
        // silently skipped (no recommendation emitted).
        let sim_outcomes: SimulationOutcomes = HashMap::new();

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-006",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_vulnerable_package_absent_from_resolved_versions_is_upgradable() {
        // The upgrade removed the vulnerable transitive dependency entirely —
        // it no longer appears in `resolved_versions` — which is treated as
        // resolved (Upgradable with an empty resolved-version string).
        let sim_outcomes = outcomes(vec![(
            "requests",
            Ok(make_sim_result("2.32.3", vec![("certifi", "2024.1.1")])),
        )]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some("2.0.7"),
            "CVE-2024-007",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

        assert_eq!(recommendations.len(), 1);
        match &recommendations[0] {
            UpgradeRecommendation::Upgradable {
                transitive_resolved_version,
                ..
            } => {
                assert!(transitive_resolved_version.is_empty());
            }
            other => panic!("expected Upgradable, got {:?}", other),
        }
    }

    #[test]
    fn test_operator_prefixed_fixed_version_is_stripped() {
        let sim_outcomes = outcomes(vec![(
            "requests",
            Ok(make_sim_result("2.32.3", vec![("urllib3", "2.2.1")])),
        )]);

        let entries = vec![make_entry(
            "urllib3",
            "1.26.5",
            Some(">= 2.0.7"), // OSV-style operator prefix
            "CVE-2024-005",
            vec![("requests", "2.31.0")],
        )];

        let recommendations = UpgradeAdvisor::advise(&entries, &sim_outcomes);

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

    // ---------------------------------------------------------------------------
    // has_prerelease_marker unit tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_prerelease_alpha_is_not_satisfied() {
        // "2.0.0a1" < "2.0.0" in PEP 440 → must not satisfy min
        assert!(!version_satisfies_min("2.0.0a1", "2.0.0"));
    }

    #[test]
    fn test_prerelease_beta_is_not_satisfied() {
        assert!(!version_satisfies_min("2.0.0b2", "2.0.0"));
    }

    #[test]
    fn test_prerelease_rc_is_not_satisfied() {
        // "2.0.0rc1" < "2.0.0" in PEP 440
        assert!(!version_satisfies_min("2.0.0rc1", "2.0.0"));
    }

    #[test]
    fn test_prerelease_dev_is_not_satisfied() {
        assert!(!version_satisfies_min("2.0.0.dev1", "2.0.0"));
    }

    #[test]
    fn test_stable_version_satisfies_equal_min() {
        // Stable "2.0.0" still satisfies ">= 2.0.0"
        assert!(version_satisfies_min("2.0.0", "2.0.0"));
    }

    // ---------------------------------------------------------------------------
    // pep440_rs migration edge cases (Issue #709)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_v_prefixed_version_is_parsed_correctly() {
        // PEP 440 permits an optional "v" prefix; pep440_rs normalizes it away,
        // so "v1.2.3" parses as 1.2.3 (unlike the old hand-rolled parser, which
        // silently dropped the "v1" segment entirely).
        assert!(version_satisfies_min("v1.2.3", "1.2.3"));
    }

    #[test]
    fn test_non_pep440_segment_falls_back_to_false() {
        // "2026.v1" is not a valid PEP 440 version (the "v1" release segment
        // cannot follow a numeric segment without a separator), so
        // Version::from_str fails and the conservative fallback applies.
        assert!(!version_satisfies_min("2026.v1", "2.0.7"));
    }

    #[test]
    fn test_calver_versions_compare_correctly() {
        assert!(version_satisfies_min("2024.1.1", "2023.7.22"));
    }

    #[test]
    fn test_post_release_now_satisfies_min_via_pep440_ordering() {
        // Behavior change from the old implementation: the old parser treated
        // any "post" marker as automatically not satisfying the minimum. Under
        // correct PEP 440 ordering, a post-release sorts after its base
        // release, so "2.0.8.post1" >= "2.0.7" is true.
        assert!(version_satisfies_min("2.0.8.post1", "2.0.7"));
    }

    #[test]
    fn test_prerelease_of_a_later_release_now_satisfies_min_via_pep440_ordering() {
        // Behavior change from the old implementation: the old parser treated
        // any prerelease marker as automatically not satisfying the minimum,
        // regardless of the release segment. Under correct PEP 440 ordering,
        // "2.1.0rc1" sorts after "2.0.0" because 2.1.0 > 2.0.0.
        assert!(version_satisfies_min("2.1.0rc1", "2.0.0"));
    }
}
