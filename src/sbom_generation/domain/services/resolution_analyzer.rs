use std::collections::HashSet;

use crate::ports::outbound::enriched_package::EnrichedPackage;
use crate::sbom_generation::domain::dependency_graph::DependencyGraph;
use crate::sbom_generation::domain::package::PackageName;
use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;

/// Stateless domain service for cross-referencing vulnerability data with the
/// dependency graph to identify which direct dependencies introduce vulnerable
/// transitive packages.
pub struct ResolutionAnalyzer;

impl ResolutionAnalyzer {
    /// Cross-reference vulnerability data with the dependency graph to produce
    /// resolution guide entries.
    ///
    /// # Algorithm
    /// 1. Collect all direct dependency names into a HashSet for fast lookup
    /// 2. For each vulnerable package, skip if it is a direct dependency
    /// 3. Reverse-lookup which direct dep(s) pull in the vulnerable transitive dep
    /// 4. For each vulnerability in that package, create a ResolutionEntry
    /// 5. Return only entries for transitive vulnerabilities
    pub fn analyze(
        dependency_graph: &DependencyGraph,
        vulnerabilities: &[PackageVulnerabilities],
        all_packages: &[EnrichedPackage],
    ) -> Vec<ResolutionEntry> {
        let direct_dep_names: HashSet<&str> = dependency_graph
            .direct_dependencies()
            .iter()
            .map(|p| p.as_str())
            .collect();

        let mut entries = Vec::new();

        for pkg_vuln in vulnerabilities {
            // Skip direct dependencies — user can upgrade them directly
            if direct_dep_names.contains(pkg_vuln.package_name()) {
                continue;
            }

            // Reverse lookup: find which direct dep(s) introduce this transitive dep
            let mut introduced_by = Vec::new();
            for (direct_dep, trans_deps) in dependency_graph.transitive_dependencies() {
                if trans_deps
                    .iter()
                    .any(|t| t.as_str() == pkg_vuln.package_name())
                {
                    let version = find_package_version(all_packages, direct_dep.as_str());
                    introduced_by.push(IntroducedBy::new(direct_dep.as_str().to_string(), version));
                }
            }

            if introduced_by.is_empty() {
                continue;
            }

            // Sort introduced_by for deterministic output
            introduced_by.sort_by(|a, b| a.package_name().cmp(b.package_name()));

            // Compute full dependency chains. If PackageName construction fails for a
            // malformed name, default to empty chains to preserve the entry.
            let dependency_chains: Vec<Vec<String>> =
                PackageName::new(pkg_vuln.package_name().to_string())
                    .map(|pkg_name| {
                        dependency_graph
                            .find_paths_to(&pkg_name)
                            .into_iter()
                            .map(|path| path.iter().map(|p| p.as_str().to_string()).collect())
                            .collect()
                    })
                    .unwrap_or_default();

            for vuln in pkg_vuln.vulnerabilities() {
                entries.push(ResolutionEntry::new(
                    pkg_vuln.package_name().to_string(),
                    pkg_vuln.current_version().to_string(),
                    vuln.fixed_version().map(|v| v.to_string()),
                    vuln.severity(),
                    vuln.id().to_string(),
                    introduced_by.clone(),
                    dependency_chains.clone(),
                ));
            }
        }

        entries
    }
}

/// Look up the version of a package by name from the enriched package list.
/// Returns "unknown" if the package is not found.
fn find_package_version(all_packages: &[EnrichedPackage], name: &str) -> String {
    all_packages
        .iter()
        .find(|p| p.package.name() == name)
        .map(|p| p.package.version().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::dependency_graph::DependencyGraph;
    use crate::sbom_generation::domain::package::PackageName;
    use crate::sbom_generation::domain::vulnerability::{Severity, Vulnerability};
    use crate::sbom_generation::domain::Package;
    use std::collections::{HashMap, HashSet, VecDeque};

    fn make_vuln(id: &str, severity: Severity, fixed: Option<&str>) -> Vulnerability {
        Vulnerability::new(
            id.to_string(),
            None,
            severity,
            fixed.map(|v| v.to_string()),
            None,
        )
        .unwrap()
    }

    fn make_pkg_vulns(
        name: &str,
        version: &str,
        vulns: Vec<Vulnerability>,
    ) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulns)
    }

    fn make_enriched(name: &str, version: &str) -> EnrichedPackage {
        EnrichedPackage::new(
            Package::new(name.to_string(), version.to_string()).unwrap(),
            None,
            None,
        )
    }

    fn make_graph(direct: Vec<&str>, transitive: Vec<(&str, Vec<&str>)>) -> DependencyGraph {
        let direct_deps: Vec<PackageName> = direct
            .iter()
            .map(|n| PackageName::new(n.to_string()).unwrap())
            .collect();

        let package_edges: HashMap<PackageName, Vec<PackageName>> = transitive
            .into_iter()
            .map(|(key, vals)| {
                let k = PackageName::new(key.to_string()).unwrap();
                let v: Vec<PackageName> = vals
                    .into_iter()
                    .map(|n| PackageName::new(n.to_string()).unwrap())
                    .collect();
                (k, v)
            })
            .collect();

        // Build flat transitive closure (direct_dep → all reachable non-direct packages)
        // to match the semantics expected by ResolutionAnalyzer::introduced_by lookup.
        let direct_set: HashSet<&PackageName> = direct_deps.iter().collect();
        let mut flat_transitive: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
        for dep in &direct_deps {
            let mut reachable: Vec<PackageName> = Vec::new();
            let mut visited: HashSet<PackageName> = HashSet::new();
            let mut queue: VecDeque<PackageName> = VecDeque::new();
            if let Some(children) = package_edges.get(dep) {
                for child in children {
                    if !direct_set.contains(child) && visited.insert(child.clone()) {
                        reachable.push(child.clone());
                        queue.push_back(child.clone());
                    }
                }
            }
            while let Some(current) = queue.pop_front() {
                if let Some(children) = package_edges.get(&current) {
                    for child in children {
                        if !direct_set.contains(child) && visited.insert(child.clone()) {
                            reachable.push(child.clone());
                            queue.push_back(child.clone());
                        }
                    }
                }
            }
            if !reachable.is_empty() {
                flat_transitive.insert(dep.clone(), reachable);
            }
        }

        DependencyGraph::new(direct_deps, flat_transitive, package_edges)
    }

    #[test]
    fn test_transitive_vulnerability_produces_entry() {
        let graph = make_graph(
            vec!["requests"],
            vec![("requests", vec!["urllib3", "certifi"])],
        );
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![make_vuln("CVE-2023-43804", Severity::High, Some("1.26.18"))],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
            make_enriched("certifi", "2023.7.22"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vulnerable_package(), "urllib3");
        assert_eq!(entries[0].current_version(), "1.26.5");
        assert_eq!(entries[0].fixed_version(), Some("1.26.18"));
        assert_eq!(entries[0].severity(), Severity::High);
        assert_eq!(entries[0].vulnerability_id(), "CVE-2023-43804");
        assert_eq!(entries[0].introduced_by().len(), 1);
        assert_eq!(entries[0].introduced_by()[0].package_name(), "requests");
        assert_eq!(entries[0].introduced_by()[0].version(), "2.28.0");
        assert_eq!(entries[0].dependency_chains().len(), 1);
        assert_eq!(entries[0].dependency_chains()[0], ["requests", "urllib3"]);
    }

    #[test]
    fn test_direct_dependency_vulnerability_is_skipped() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let vulns = vec![make_pkg_vulns(
            "requests",
            "2.28.0",
            vec![make_vuln("CVE-2024-0001", Severity::Medium, Some("2.29.0"))],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert!(entries.is_empty());
    }

    #[test]
    fn test_multiple_direct_deps_introduce_same_vulnerable_package() {
        let graph = make_graph(
            vec!["requests", "httpx"],
            vec![
                ("requests", vec!["urllib3"]),
                ("httpx", vec!["urllib3", "httpcore"]),
            ],
        );
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![make_vuln("CVE-2023-43804", Severity::High, Some("1.26.18"))],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("httpx", "0.23.0"),
            make_enriched("urllib3", "1.26.5"),
            make_enriched("httpcore", "0.16.0"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].introduced_by().len(), 2);
        // Sorted alphabetically
        assert_eq!(entries[0].introduced_by()[0].package_name(), "httpx");
        assert_eq!(entries[0].introduced_by()[1].package_name(), "requests");
        // Both direct deps produce a chain to urllib3
        assert_eq!(entries[0].dependency_chains().len(), 2);
        let chains = entries[0].dependency_chains();
        assert!(chains.contains(&vec!["requests".to_string(), "urllib3".to_string()]));
        assert!(chains.contains(&vec!["httpx".to_string(), "urllib3".to_string()]));
    }

    #[test]
    fn test_empty_dependency_graph_returns_empty() {
        let graph = make_graph(vec![], vec![]);
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![make_vuln("CVE-2023-43804", Severity::High, None)],
        )];
        let packages = vec![make_enriched("urllib3", "1.26.5")];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert!(entries.is_empty());
    }

    #[test]
    fn test_empty_vulnerabilities_returns_empty() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let vulns: Vec<PackageVulnerabilities> = vec![];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert!(entries.is_empty());
    }

    #[test]
    fn test_package_not_found_in_transitive_list_is_omitted() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        // "unknown-pkg" is not in any transitive dep list
        let vulns = vec![make_pkg_vulns(
            "unknown-pkg",
            "0.1.0",
            vec![make_vuln("CVE-2024-9999", Severity::Critical, None)],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
            make_enriched("unknown-pkg", "0.1.0"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert!(entries.is_empty());
    }

    #[test]
    fn test_multiple_vulnerabilities_in_same_package() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![
                make_vuln("CVE-2023-43804", Severity::High, Some("1.26.18")),
                make_vuln("CVE-2023-45803", Severity::Medium, Some("2.0.7")),
            ],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].vulnerability_id(), "CVE-2023-43804");
        assert_eq!(entries[1].vulnerability_id(), "CVE-2023-45803");
        // Both entries share the same introduced_by
        assert_eq!(entries[0].introduced_by()[0].package_name(), "requests");
        assert_eq!(entries[1].introduced_by()[0].package_name(), "requests");
    }

    #[test]
    fn test_unknown_version_when_package_not_in_enriched_list() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![make_vuln("CVE-2023-43804", Severity::High, None)],
        )];
        // "requests" is NOT in the all_packages list
        let packages = vec![make_enriched("urllib3", "1.26.5")];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].introduced_by()[0].package_name(), "requests");
        assert_eq!(entries[0].introduced_by()[0].version(), "unknown");
    }

    #[test]
    fn test_analyze_populates_dependency_chains_deep_transitive() {
        // a -> b -> vuln (two-hop chain)
        let graph = make_graph(vec!["a"], vec![("a", vec!["b"]), ("b", vec!["vuln"])]);
        let vulns = vec![make_pkg_vulns(
            "vuln",
            "0.1.0",
            vec![make_vuln("CVE-2024-1111", Severity::High, None)],
        )];
        let packages = vec![
            make_enriched("a", "1.0.0"),
            make_enriched("b", "2.0.0"),
            make_enriched("vuln", "0.1.0"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dependency_chains().len(), 1);
        assert_eq!(entries[0].dependency_chains()[0], ["a", "b", "vuln"]);
    }

    #[test]
    fn test_analyze_dependency_chains_shared_across_multiple_vulns_same_package() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let vulns = vec![make_pkg_vulns(
            "urllib3",
            "1.26.5",
            vec![
                make_vuln("CVE-2023-43804", Severity::High, Some("1.26.18")),
                make_vuln("CVE-2023-45803", Severity::Medium, Some("2.0.7")),
            ],
        )];
        let packages = vec![
            make_enriched("requests", "2.28.0"),
            make_enriched("urllib3", "1.26.5"),
        ];

        let entries = ResolutionAnalyzer::analyze(&graph, &vulns, &packages);

        assert_eq!(entries.len(), 2);
        // Both entries for the same package share the same chains
        assert_eq!(
            entries[0].dependency_chains(),
            entries[1].dependency_chains()
        );
        assert_eq!(entries[0].dependency_chains()[0], ["requests", "urllib3"]);
    }
}
