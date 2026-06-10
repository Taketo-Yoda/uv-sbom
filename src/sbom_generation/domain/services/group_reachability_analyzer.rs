use crate::sbom_generation::domain::Package;
use std::collections::{HashMap, HashSet, VecDeque};

/// Pure domain service that determines which packages should be retained
/// in a production SBOM after excluding specified dependency groups.
///
/// Performs BFS graph traversal to distinguish packages exclusively reachable
/// from dev/optional groups (safe to exclude) from those on any production path
/// (must be retained).
#[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
pub struct GroupReachabilityAnalyzer;

impl GroupReachabilityAnalyzer {
    /// Returns the subset of `all_packages` after removing packages that are
    /// exclusively reachable from the specified dependency groups.
    ///
    /// A package is excluded only when:
    /// - It is reachable from at least one excluded group root, AND
    /// - It is NOT reachable from any production root.
    ///
    /// Production roots are packages in `dep_graph` that have no incoming edges
    /// and are not roots of any excluded group.
    ///
    /// Unknown group names in `groups_to_exclude` are silently ignored.
    #[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
    pub fn filter_excluded_groups(
        all_packages: &[Package],
        dep_graph: &HashMap<String, Vec<String>>,
        group_roots: &HashMap<String, Vec<String>>,
        groups_to_exclude: &[String],
    ) -> Vec<Package> {
        if groups_to_exclude.is_empty() {
            return all_packages.to_vec();
        }

        let excluded_root_names = collect_excluded_root_names(group_roots, groups_to_exclude);
        let production_reachable =
            compute_production_reachable(dep_graph, &excluded_root_names);
        let exclude_set =
            compute_exclude_set(dep_graph, group_roots, groups_to_exclude, &production_reachable);

        all_packages
            .iter()
            .filter(|p| !exclude_set.contains(p.name()))
            .cloned()
            .collect()
    }
}

#[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
fn collect_excluded_root_names<'a>(
    group_roots: &'a HashMap<String, Vec<String>>,
    groups_to_exclude: &[String],
) -> HashSet<&'a str> {
    groups_to_exclude
        .iter()
        .filter_map(|g| group_roots.get(g.as_str()))
        .flat_map(|roots| roots.iter().map(|s| s.as_str()))
        .collect()
}

#[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
fn compute_production_reachable(
    dep_graph: &HashMap<String, Vec<String>>,
    excluded_root_names: &HashSet<&str>,
) -> HashSet<String> {
    let mut has_parent: HashSet<&str> = HashSet::new();
    for deps in dep_graph.values() {
        for dep in deps {
            has_parent.insert(dep.as_str());
        }
    }

    // Production seeds: DAG roots that are not an excluded-group root.
    let seeds: Vec<&str> = dep_graph
        .keys()
        .map(|k| k.as_str())
        .filter(|name| !has_parent.contains(name) && !excluded_root_names.contains(name))
        .collect();

    bfs_reachable(dep_graph, &seeds)
}

#[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
fn compute_exclude_set(
    dep_graph: &HashMap<String, Vec<String>>,
    group_roots: &HashMap<String, Vec<String>>,
    groups_to_exclude: &[String],
    production_reachable: &HashSet<String>,
) -> HashSet<String> {
    let mut exclude_set = HashSet::new();
    for group in groups_to_exclude {
        let Some(roots) = group_roots.get(group.as_str()) else {
            continue;
        };
        let seeds: Vec<&str> = roots.iter().map(|s| s.as_str()).collect();
        let group_reachable = bfs_reachable(dep_graph, &seeds);
        for pkg in group_reachable {
            if !production_reachable.contains(&pkg) {
                exclude_set.insert(pkg);
            }
        }
    }
    exclude_set
}

#[allow(dead_code)] // WIRE(#629): remove when GenerateSbomUseCase calls filter_excluded_groups
fn bfs_reachable(dep_graph: &HashMap<String, Vec<String>>, seeds: &[&str]) -> HashSet<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for &seed in seeds {
        if visited.insert(seed.to_string()) {
            queue.push_back(seed.to_string());
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(deps) = dep_graph.get(&current) {
            for dep in deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    visited
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str) -> Package {
        Package::new(name.to_string(), "1.0.0".to_string()).unwrap()
    }

    /// Build a dep_graph ensuring every mentioned package appears as a key.
    fn make_dep_graph(edges: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for &(parent, deps) in edges {
            let entry = map.entry(parent.to_string()).or_default();
            for &dep in deps {
                entry.push(dep.to_string());
            }
            for &dep in deps {
                map.entry(dep.to_string()).or_default();
            }
        }
        map
    }

    fn make_group_roots(groups: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        groups
            .iter()
            .map(|&(g, roots)| {
                (
                    g.to_string(),
                    roots.iter().map(|s| s.to_string()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn test_production_only_package_retained() {
        let all_packages = vec![pkg("myapp"), pkg("requests"), pkg("urllib3")];
        let dep_graph = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &["urllib3"]),
            ("urllib3", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string()],
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"urllib3"));
    }

    #[test]
    fn test_dev_only_package_excluded() {
        let all_packages = vec![
            pkg("myapp"),
            pkg("requests"),
            pkg("pytest"),
            pkg("iniconfig"),
        ];
        let dep_graph = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &[]),
            ("pytest", &["iniconfig"]),
            ("iniconfig", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string()],
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"pytest"), "dev root must be excluded");
        assert!(!names.contains(&"iniconfig"), "dev transitive must be excluded");
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }

    #[test]
    fn test_shared_package_retained() {
        // certifi is reachable from both production (requests) and dev (pytest)
        let all_packages = vec![
            pkg("myapp"),
            pkg("requests"),
            pkg("certifi"),
            pkg("pytest"),
        ];
        let dep_graph = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &["certifi"]),
            ("pytest", &["certifi"]),
            ("certifi", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string()],
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"certifi"), "shared package must be retained");
        assert!(!names.contains(&"pytest"), "dev-only root must be excluded");
    }

    #[test]
    fn test_unknown_group_name_ignored() {
        let all_packages = vec![pkg("myapp"), pkg("requests")];
        let dep_graph = make_dep_graph(&[("myapp", &["requests"]), ("requests", &[])]);
        let group_roots: HashMap<String, Vec<String>> = HashMap::new();

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["nonexistent".to_string()],
        );

        assert_eq!(result.len(), all_packages.len());
    }

    #[test]
    fn test_empty_groups_to_exclude_returns_all() {
        let all_packages = vec![pkg("requests"), pkg("urllib3"), pkg("pytest")];
        let dep_graph =
            make_dep_graph(&[("requests", &["urllib3"]), ("urllib3", &[]), ("pytest", &[])]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &[],
        );

        assert_eq!(result.len(), all_packages.len());
    }

    #[test]
    fn test_multiple_groups_all_exclusive_packages_excluded() {
        let all_packages = vec![
            pkg("myapp"),
            pkg("requests"),
            pkg("pytest"),
            pkg("ruff"),
            pkg("iniconfig"),
        ];
        let dep_graph = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &[]),
            ("pytest", &["iniconfig"]),
            ("iniconfig", &[]),
            ("ruff", &[]),
        ]);
        let group_roots =
            make_group_roots(&[("dev", &["pytest"]), ("lint", &["ruff"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string(), "lint".to_string()],
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"pytest"));
        assert!(!names.contains(&"iniconfig"));
        assert!(!names.contains(&"ruff"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }

    #[test]
    fn test_cycle_in_dep_graph_handled_safely() {
        // a -> b -> a (cycle), plus prod: myapp -> requests
        let all_packages = vec![pkg("myapp"), pkg("requests"), pkg("a"), pkg("b")];
        let dep_graph = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &[]),
            ("a", &["b"]),
            ("b", &["a"]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["a"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string()],
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"a"));
        assert!(!names.contains(&"b"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }
}
