use crate::sbom_generation::domain::Package;
use std::collections::{HashMap, HashSet, VecDeque};

/// Pure domain service that determines which packages should be retained
/// in a production SBOM after excluding specified dependency groups.
///
/// Performs BFS graph traversal to distinguish packages exclusively reachable
/// from dev/optional groups (safe to exclude) from those on any production path
/// (must be retained).
pub struct GroupReachabilityAnalyzer;

/// How a root listed by both an excluded and a non-excluded group is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedRootPolicy {
    /// The root counts as excluded (single-project semantics).
    ExcludedWins,
    /// Every root of a non-excluded group is a production seed, even one with
    /// a parent inside an excluded group's subtree, so a non-excluded group
    /// keeps everything it reaches (workspace members, #1001).
    KeptGroupWins,
}

impl GroupReachabilityAnalyzer {
    /// Returns the subset of `all_packages` after removing packages that are
    /// exclusively reachable from the specified dependency groups.
    ///
    /// A package is excluded only when:
    /// - It is reachable from at least one excluded group root, AND
    /// - It is NOT reachable from any production root.
    ///
    /// Production roots are packages in `dep_graph` that have no incoming edges
    /// and are not excluded roots. With [`SharedRootPolicy::KeptGroupWins`], the
    /// roots of every group not in `groups_to_exclude` are production roots too.
    ///
    /// Unknown group names in `groups_to_exclude` are silently ignored.
    pub fn filter_excluded_groups(
        all_packages: &[Package],
        dep_graph: &HashMap<String, Vec<String>>,
        group_roots: &HashMap<String, Vec<String>>,
        groups_to_exclude: &[String],
        policy: SharedRootPolicy,
    ) -> Vec<Package> {
        if groups_to_exclude.is_empty() {
            return all_packages.to_vec();
        }

        let excluded_root_names = collect_excluded_root_names(group_roots, groups_to_exclude);
        let kept_group_roots = match policy {
            SharedRootPolicy::ExcludedWins => Vec::new(),
            SharedRootPolicy::KeptGroupWins => {
                collect_kept_group_roots(group_roots, groups_to_exclude)
            }
        };
        let production_reachable =
            compute_production_reachable(dep_graph, &excluded_root_names, &kept_group_roots);
        let exclude_set = compute_exclude_set(
            dep_graph,
            group_roots,
            groups_to_exclude,
            &production_reachable,
        );

        all_packages
            .iter()
            .filter(|p| !exclude_set.contains(p.name()))
            .cloned()
            .collect()
    }
}

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

/// Roots of every group not in `groups_to_exclude`.
fn collect_kept_group_roots<'a>(
    group_roots: &'a HashMap<String, Vec<String>>,
    groups_to_exclude: &[String],
) -> Vec<&'a str> {
    group_roots
        .iter()
        .filter(|(group, _)| !groups_to_exclude.contains(group))
        .flat_map(|(_, roots)| roots.iter().map(|s| s.as_str()))
        .collect()
}

fn compute_production_reachable(
    dep_graph: &HashMap<String, Vec<String>>,
    excluded_root_names: &HashSet<&str>,
    extra_seeds: &[&str],
) -> HashSet<String> {
    let mut has_parent: HashSet<&str> = HashSet::new();
    for deps in dep_graph.values() {
        for dep in deps {
            has_parent.insert(dep.as_str());
        }
    }

    // Production seeds: DAG roots that are not an excluded-group root, plus
    // `extra_seeds` (kept group roots under `KeptGroupWins`), whatever their parents.
    let seeds: Vec<&str> = dep_graph
        .keys()
        .map(|k| k.as_str())
        .filter(|name| !has_parent.contains(name) && !excluded_root_names.contains(name))
        .chain(extra_seeds.iter().copied())
        .collect();

    bfs_reachable(dep_graph, &seeds)
}

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
            .map(|&(g, roots)| (g.to_string(), roots.iter().map(|s| s.to_string()).collect()))
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
            SharedRootPolicy::ExcludedWins,
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
            SharedRootPolicy::ExcludedWins,
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"pytest"), "dev root must be excluded");
        assert!(
            !names.contains(&"iniconfig"),
            "dev transitive must be excluded"
        );
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }

    #[test]
    fn test_shared_package_retained() {
        // certifi is reachable from both production (requests) and dev (pytest)
        let all_packages = vec![pkg("myapp"), pkg("requests"), pkg("certifi"), pkg("pytest")];
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
            SharedRootPolicy::ExcludedWins,
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(
            names.contains(&"certifi"),
            "shared package must be retained"
        );
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
            SharedRootPolicy::ExcludedWins,
        );

        assert_eq!(result.len(), all_packages.len());
    }

    #[test]
    fn test_empty_groups_to_exclude_returns_all() {
        let all_packages = vec![pkg("requests"), pkg("urllib3"), pkg("pytest")];
        let dep_graph = make_dep_graph(&[
            ("requests", &["urllib3"]),
            ("urllib3", &[]),
            ("pytest", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &[],
            SharedRootPolicy::ExcludedWins,
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
        let group_roots = make_group_roots(&[("dev", &["pytest"]), ("lint", &["ruff"])]);

        let result = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["dev".to_string(), "lint".to_string()],
            SharedRootPolicy::ExcludedWins,
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
            SharedRootPolicy::ExcludedWins,
        );

        let names: Vec<&str> = result.iter().map(|p| p.name()).collect();
        assert!(!names.contains(&"a"));
        assert!(!names.contains(&"b"));
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }

    // --- SharedRootPolicy (#1001) ---

    /// A dependency graph or a group-roots map.
    type Graph = HashMap<String, Vec<String>>;

    /// Member `b`: runtime dep `requests`; `docs = [sphinx]` and `lint = [sphinx]`
    /// share a root, `sphinx -> docutils`; `test = [pytest]` is its own.
    fn shared_root_fixture() -> (Vec<Package>, Graph, Graph) {
        let all_packages = vec![
            pkg("b"),
            pkg("requests"),
            pkg("sphinx"),
            pkg("docutils"),
            pkg("pytest"),
        ];
        let dep_graph = make_dep_graph(&[
            ("b", &["requests"]),
            ("requests", &[]),
            ("sphinx", &["docutils"]),
            ("docutils", &[]),
            ("pytest", &[]),
        ]);
        let group_roots = make_group_roots(&[
            ("docs", &["sphinx"]),
            ("lint", &["sphinx"]),
            ("test", &["pytest"]),
        ]);
        (all_packages, dep_graph, group_roots)
    }

    fn names_with_policy(groups: &[&str], policy: SharedRootPolicy) -> Vec<String> {
        let (all_packages, dep_graph, group_roots) = shared_root_fixture();
        GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &groups.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
            policy,
        )
        .iter()
        .map(|p| p.name().to_string())
        .collect()
    }

    #[test]
    fn test_kept_group_wins_retains_root_shared_with_non_excluded_group() {
        let names = names_with_policy(&["docs"], SharedRootPolicy::KeptGroupWins);
        assert!(names.contains(&"sphinx".to_string()), "lint still lists it");
        assert!(
            names.contains(&"docutils".to_string()),
            "a transitive dep of the shared root is retained"
        );
        assert!(names.contains(&"pytest".to_string()));
    }

    #[test]
    fn test_excluded_wins_drops_root_shared_with_non_excluded_group() {
        // Pins the single-project semantics (`project_scope::filter_by_groups`).
        let names = names_with_policy(&["docs"], SharedRootPolicy::ExcludedWins);
        assert!(!names.contains(&"sphinx".to_string()));
        assert!(!names.contains(&"docutils".to_string()));
        assert!(names.contains(&"requests".to_string()));
    }

    #[test]
    fn test_kept_group_wins_drops_root_when_every_listing_group_is_excluded() {
        let names = names_with_policy(&["docs", "lint"], SharedRootPolicy::KeptGroupWins);
        assert!(!names.contains(&"sphinx".to_string()));
        assert!(!names.contains(&"docutils".to_string()));
        assert!(names.contains(&"pytest".to_string()));
        assert!(names.contains(&"requests".to_string()));
    }

    #[test]
    fn test_kept_group_wins_drops_unshared_root_of_excluded_group() {
        let names = names_with_policy(&["test"], SharedRootPolicy::KeptGroupWins);
        assert!(!names.contains(&"pytest".to_string()));
        assert!(names.contains(&"sphinx".to_string()));
    }

    #[test]
    fn test_kept_group_wins_retains_kept_root_reached_from_excluded_subtree() {
        // `docs = [furo]`, `furo -> sphinx`, `lint = [sphinx]`: `sphinx` has a
        // parent, so only an explicit seed keeps it when `docs` is excluded.
        let all_packages = vec![pkg("b"), pkg("furo"), pkg("sphinx"), pkg("docutils")];
        let dep_graph = make_dep_graph(&[
            ("b", &[]),
            ("furo", &["sphinx"]),
            ("sphinx", &["docutils"]),
            ("docutils", &[]),
        ]);
        let group_roots = make_group_roots(&[("docs", &["furo"]), ("lint", &["sphinx"])]);
        let names = |policy| -> Vec<String> {
            GroupReachabilityAnalyzer::filter_excluded_groups(
                &all_packages,
                &dep_graph,
                &group_roots,
                &["docs".to_string()],
                policy,
            )
            .iter()
            .map(|p| p.name().to_string())
            .collect()
        };

        let kept = names(SharedRootPolicy::KeptGroupWins);
        assert!(!kept.contains(&"furo".to_string()));
        assert!(kept.contains(&"sphinx".to_string()));
        assert!(kept.contains(&"docutils".to_string()));

        let excluded = names(SharedRootPolicy::ExcludedWins);
        assert!(!excluded.contains(&"sphinx".to_string()));
    }

    #[test]
    fn test_kept_group_wins_matches_excluded_wins_when_all_groups_excluded() {
        let all = ["docs", "lint", "test"];
        assert_eq!(
            names_with_policy(&all, SharedRootPolicy::KeptGroupWins),
            names_with_policy(&all, SharedRootPolicy::ExcludedWins)
        );
    }
}
