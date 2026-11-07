use crate::sbom_generation::domain::package::normalize_name;
use crate::sbom_generation::domain::Package;
use std::collections::{HashMap, HashSet, VecDeque};

/// Pure domain service that determines which packages should be retained
/// in a production SBOM after excluding specified dependency groups.
///
/// Performs BFS graph traversal to distinguish packages exclusively reachable
/// from dev/optional groups (safe to exclude) from those on any production path
/// (must be retained).
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
    /// and are not excluded roots, plus every root of a group not in
    /// `groups_to_exclude` — even one with a parent inside an excluded group's
    /// subtree — so a non-excluded group keeps everything it reaches (#1001, #1005).
    ///
    /// Group names are compared after PEP 735 normalization (`normalize_name`),
    /// on both the `groups_to_exclude` and the `group_roots` side: case is
    /// ignored and runs of `-`, `_`, `.` match a single `-` (#1015). Unknown
    /// group names in `groups_to_exclude` are silently ignored.
    pub fn filter_excluded_groups(
        all_packages: &[Package],
        dep_graph: &HashMap<String, Vec<String>>,
        group_roots: &HashMap<String, Vec<String>>,
        groups_to_exclude: &[String],
    ) -> Vec<Package> {
        if groups_to_exclude.is_empty() {
            return all_packages.to_vec();
        }

        let (excluded_root_names, kept_group_roots) =
            partition_group_roots(group_roots, groups_to_exclude);
        let production_reachable =
            compute_production_reachable(dep_graph, &excluded_root_names, &kept_group_roots);
        let exclude_set =
            compute_exclude_set(dep_graph, &excluded_root_names, &production_reachable);

        all_packages
            .iter()
            .filter(|p| !exclude_set.contains(p.name()))
            .cloned()
            .collect()
    }
}

/// Splits the group roots into the roots of excluded groups and the roots of
/// every other group, matching group names after normalization so that two
/// spellings of one group are never split across the two sets.
fn partition_group_roots<'a>(
    group_roots: &'a HashMap<String, Vec<String>>,
    groups_to_exclude: &[String],
) -> (HashSet<&'a str>, Vec<&'a str>) {
    let excluded: HashSet<String> = groups_to_exclude
        .iter()
        .map(|group| normalize_name(group))
        .collect();

    let mut excluded_root_names = HashSet::new();
    let mut kept_group_roots = Vec::new();
    for (group, roots) in group_roots {
        let roots = roots.iter().map(String::as_str);
        if excluded.contains(&normalize_name(group)) {
            excluded_root_names.extend(roots);
        } else {
            kept_group_roots.extend(roots);
        }
    }
    (excluded_root_names, kept_group_roots)
}

fn compute_production_reachable(
    dep_graph: &HashMap<String, Vec<String>>,
    excluded_root_names: &HashSet<&str>,
    kept_group_roots: &[&str],
) -> HashSet<String> {
    let mut has_parent: HashSet<&str> = HashSet::new();
    for deps in dep_graph.values() {
        for dep in deps {
            has_parent.insert(dep.as_str());
        }
    }

    // Production seeds: DAG roots that are not an excluded-group root, plus
    // the kept group roots, whatever their parents.
    let seeds: Vec<&str> = dep_graph
        .keys()
        .map(|k| k.as_str())
        .filter(|name| !has_parent.contains(name) && !excluded_root_names.contains(name))
        .chain(kept_group_roots.iter().copied())
        .collect();

    bfs_reachable(dep_graph, &seeds)
}

/// Packages reachable from an excluded group's root but from no production
/// root.
fn compute_exclude_set(
    dep_graph: &HashMap<String, Vec<String>>,
    excluded_root_names: &HashSet<&str>,
    production_reachable: &HashSet<String>,
) -> HashSet<String> {
    let seeds: Vec<&str> = excluded_root_names.iter().copied().collect();
    bfs_reachable(dep_graph, &seeds)
        .into_iter()
        .filter(|pkg| !production_reachable.contains(pkg))
        .collect()
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

    // --- Roots shared between groups (#1001, #1005) ---

    /// A dependency graph or a group-roots map.
    type Graph = HashMap<String, Vec<String>>;

    /// Project `b`: runtime dep `requests`; `docs = [sphinx]` and `lint = [sphinx]`
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

    fn names_excluding(groups: &[&str]) -> Vec<String> {
        let (all_packages, dep_graph, group_roots) = shared_root_fixture();
        GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &groups.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        )
        .iter()
        .map(|p| p.name().to_string())
        .collect()
    }

    #[test]
    fn test_retains_root_shared_with_non_excluded_group() {
        // Single-project mode formerly dropped the shared root (an excluded-wins
        // policy). #1005 made this the only behavior: the project still installs
        // a root that a non-excluded group lists, so dropping it under-reported
        // the SBOM.
        let names = names_excluding(&["docs"]);
        assert!(names.contains(&"sphinx".to_string()), "lint still lists it");
        assert!(
            names.contains(&"docutils".to_string()),
            "a transitive dep of the shared root is retained"
        );
        assert!(names.contains(&"pytest".to_string()));
        assert!(names.contains(&"requests".to_string()));
    }

    #[test]
    fn test_drops_shared_root_when_every_listing_group_is_excluded() {
        let names = names_excluding(&["docs", "lint"]);
        assert!(!names.contains(&"sphinx".to_string()));
        assert!(!names.contains(&"docutils".to_string()));
        assert!(names.contains(&"pytest".to_string()));
        assert!(names.contains(&"requests".to_string()));
    }

    #[test]
    fn test_drops_unshared_root_of_excluded_group() {
        let names = names_excluding(&["test"]);
        assert!(!names.contains(&"pytest".to_string()));
        assert!(names.contains(&"sphinx".to_string()));
    }

    #[test]
    fn test_retains_kept_root_reached_from_excluded_subtree() {
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

        let kept: Vec<String> = GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &group_roots,
            &["docs".to_string()],
        )
        .iter()
        .map(|p| p.name().to_string())
        .collect();

        assert!(!kept.contains(&"furo".to_string()));
        assert!(kept.contains(&"sphinx".to_string()));
        assert!(kept.contains(&"docutils".to_string()));
    }

    #[test]
    fn test_excluding_every_group_keeps_only_runtime_packages() {
        assert_eq!(
            names_excluding(&["docs", "lint", "test"]),
            vec!["b", "requests"]
        );
    }

    // --- PEP 735 group name normalization (#1015) ---

    /// Project `app`: runtime dep `requests`; `lint = [ruff]` and
    /// `type-check = [mypy]`, `mypy -> typing-extensions`.
    fn kept_names(group_roots: &[(&str, &[&str])], exclude: &[&str]) -> Vec<String> {
        let all_packages = vec![
            pkg("app"),
            pkg("requests"),
            pkg("ruff"),
            pkg("black"),
            pkg("mypy"),
            pkg("typing-extensions"),
        ];
        let dep_graph = make_dep_graph(&[
            ("app", &["requests"]),
            ("requests", &[]),
            ("ruff", &[]),
            ("black", &[]),
            ("mypy", &["typing-extensions"]),
            ("typing-extensions", &[]),
        ]);
        GroupReachabilityAnalyzer::filter_excluded_groups(
            &all_packages,
            &dep_graph,
            &make_group_roots(group_roots),
            &exclude.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        )
        .iter()
        .map(|p| p.name().to_string())
        .collect()
    }

    const LINT_AND_TYPE_CHECK: &[(&str, &[&str])] =
        &[("lint", &["ruff"]), ("type-check", &["mypy"])];

    #[test]
    fn test_excluded_group_name_matches_case_insensitively() {
        for spelling in ["Lint", "LINT", "lint"] {
            let names = kept_names(LINT_AND_TYPE_CHECK, &[spelling]);
            assert!(!names.contains(&"ruff".to_string()), "{spelling}");
            assert!(names.contains(&"mypy".to_string()), "{spelling}");
            assert!(names.contains(&"requests".to_string()), "{spelling}");
        }
    }

    #[test]
    fn test_excluded_group_name_matches_across_separators() {
        for spelling in ["type_check", "Type.Check", "type-check"] {
            let names = kept_names(LINT_AND_TYPE_CHECK, &[spelling]);
            assert!(!names.contains(&"mypy".to_string()), "{spelling}");
            assert!(
                !names.contains(&"typing-extensions".to_string()),
                "{spelling}"
            );
            assert!(names.contains(&"ruff".to_string()), "{spelling}");
        }
    }

    #[test]
    fn test_excluded_group_name_collapses_separator_runs() {
        for spelling in ["type__check", "Type-_.Check"] {
            let names = kept_names(LINT_AND_TYPE_CHECK, &[spelling]);
            assert!(!names.contains(&"mypy".to_string()), "{spelling}");
        }
    }

    #[test]
    fn test_lockfile_group_name_is_normalized_before_matching() {
        let names = kept_names(&[("Type_Check", &["mypy"])], &["type-check"]);
        assert!(!names.contains(&"mypy".to_string()));
        assert!(!names.contains(&"typing-extensions".to_string()));
    }

    #[test]
    fn test_normalized_exclusion_removes_group_from_kept_roots() {
        // `lint` must not stay a kept group because it was spelled `LINT`:
        // its root `sphinx` would be re-seeded and retained.
        let names = names_excluding(&["Docs", "LINT"]);
        assert!(!names.contains(&"sphinx".to_string()));
        assert!(!names.contains(&"docutils".to_string()));
        assert!(names.contains(&"pytest".to_string()));
    }

    #[test]
    fn test_lockfile_groups_normalizing_to_same_name_are_excluded_together() {
        let names = kept_names(&[("lint", &["ruff"]), ("Lint", &["black"])], &["lint"]);
        assert!(!names.contains(&"ruff".to_string()));
        assert!(!names.contains(&"black".to_string()));
    }

    #[test]
    fn test_non_matching_normalized_name_is_ignored() {
        let names = kept_names(LINT_AND_TYPE_CHECK, &["lint-extra", "type"]);
        assert!(names.contains(&"ruff".to_string()));
        assert!(names.contains(&"mypy".to_string()));
    }
}
