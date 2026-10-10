use crate::sbom_generation::domain::{DependencyGraph, PackageName};
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

/// A record describing a transitive dependency chain that was truncated because it
/// exceeded [`DependencyAnalyzer::MAX_RECURSION_DEPTH`].
///
/// Pure data, no I/O: rendering/localizing this record (e.g. printing a warning) is
/// the responsibility of the application or CLI layer, which has `Locale`/`Messages`
/// in scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedChainRecord {
    /// The name of the package whose dependency chain was truncated
    pub package_name: String,
    /// The recursion depth limit that was reached
    pub max_depth: usize,
}

/// DependencyAnalyzer service for analyzing transitive dependencies
///
/// This service contains pure business logic for dependency graph analysis.
/// It has no I/O dependencies and works only with domain objects: recursion-depth
/// truncation is reported via a returned `Vec<TruncatedChainRecord>` rather than by
/// printing directly.
pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    /// Analyzes dependencies and builds a DependencyGraph
    ///
    /// # Arguments
    /// * `project_name` - The name of the root project
    /// * `dependency_map` - Map of package name to its dependencies
    ///
    /// # Returns
    /// A tuple of:
    /// * A DependencyGraph containing direct dependencies and transitive dependencies
    /// * The list of `TruncatedChainRecord`s describing every dependency chain that hit
    ///   the recursion-depth guard (see [`Self::MAX_RECURSION_DEPTH`])
    ///
    /// # Errors
    /// Returns an error if any package name in `dependency_map` fails `PackageName`
    /// validation.
    pub fn analyze(
        project_name: &PackageName,
        dependency_map: &HashMap<String, Vec<String>>,
    ) -> Result<(DependencyGraph, Vec<TruncatedChainRecord>)> {
        // Extract direct dependencies for the project
        let direct_deps = dependency_map
            .get(project_name.as_str())
            .cloned()
            .unwrap_or_default();

        let direct_deps_names: Vec<PackageName> = direct_deps
            .iter()
            .map(|name| PackageName::new(name.clone()))
            .collect::<Result<Vec<_>>>()?;

        // Build transitive dependency map
        let direct_deps_set: HashSet<String> = direct_deps.iter().cloned().collect();
        let mut transitive_dependencies: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
        let mut truncated_chains: Vec<TruncatedChainRecord> = Vec::new();

        for direct_dep in &direct_deps {
            let mut trans_deps = Vec::new();
            let mut visited = HashSet::new();

            Self::collect_transitive_deps(
                direct_dep,
                dependency_map,
                &mut trans_deps,
                &mut visited,
                &direct_deps_set,
                0, // Start with depth 0
                &mut truncated_chains,
            );

            if !trans_deps.is_empty() {
                let direct_dep_name = PackageName::new(direct_dep.clone())?;
                let trans_dep_names: Vec<PackageName> = trans_deps
                    .iter()
                    .map(|name| PackageName::new(name.clone()))
                    .collect::<Result<Vec<_>>>()?;
                transitive_dependencies.insert(direct_dep_name, trans_dep_names);
            }
        }

        let package_edges = Self::build_package_edges(project_name, dependency_map)?;

        Ok((
            DependencyGraph::new(direct_deps_names, transitive_dependencies, package_edges),
            truncated_chains,
        ))
    }

    /// Builds an edge map of `pkg → immediate children` for every package in
    /// `dependency_map` except the project root. This map is consumed by
    /// [`DependencyGraph::find_paths_to`] for multi-hop BFS path traversal.
    fn build_package_edges(
        project_name: &PackageName,
        dependency_map: &HashMap<String, Vec<String>>,
    ) -> Result<HashMap<PackageName, Vec<PackageName>>> {
        let mut package_edges: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
        for (parent, children) in dependency_map {
            if parent == project_name.as_str() {
                continue;
            }
            let parent_name = PackageName::new(parent.clone())?;
            let child_names: Vec<PackageName> = children
                .iter()
                .map(|n| PackageName::new(n.clone()))
                .collect::<Result<Vec<_>>>()?;
            package_edges.insert(parent_name, child_names);
        }
        Ok(package_edges)
    }

    /// Maximum recursion depth to prevent stack overflow attacks
    /// This limits dependency chains to prevent malicious lockfiles from causing DoS
    const MAX_RECURSION_DEPTH: usize = 100;

    /// Recursively collects transitive dependencies for a package
    ///
    /// This is a pure algorithm with no I/O operations. When the recursion-depth guard
    /// trips, a [`TruncatedChainRecord`] is pushed onto `truncated` instead of printing
    /// anything — the caller decides whether and how to report it.
    ///
    /// # Arguments
    /// * `package_name` - The package to analyze
    /// * `dependency_map` - Map of package name to its dependencies
    /// * `trans_deps` - Accumulated transitive dependencies
    /// * `visited` - Set of already visited packages (cycle detection)
    /// * `direct_deps` - Set of direct dependencies (to exclude from transitive)
    /// * `depth` - Current recursion depth (for DoS prevention)
    /// * `truncated` - Accumulated records of dependency chains that hit the recursion
    ///   depth guard
    #[allow(clippy::too_many_arguments)]
    fn collect_transitive_deps(
        package_name: &str,
        dependency_map: &HashMap<String, Vec<String>>,
        trans_deps: &mut Vec<String>,
        visited: &mut HashSet<String>,
        direct_deps: &HashSet<String>,
        depth: usize,
        truncated: &mut Vec<TruncatedChainRecord>,
    ) {
        // Security: Prevent excessive recursion (DoS protection)
        if depth >= Self::MAX_RECURSION_DEPTH {
            truncated.push(TruncatedChainRecord {
                package_name: package_name.to_string(),
                max_depth: Self::MAX_RECURSION_DEPTH,
            });
            return;
        }

        if visited.contains(package_name) {
            return;
        }
        visited.insert(package_name.to_string());

        if let Some(dependencies) = dependency_map.get(package_name) {
            for dep in dependencies {
                // Only include as transitive if not a direct dependency
                if !direct_deps.contains(dep) && !trans_deps.contains(dep) {
                    trans_deps.push(dep.clone());
                }
                // Recursively collect transitive dependencies with incremented depth
                Self::collect_transitive_deps(
                    dep,
                    dependency_map,
                    trans_deps,
                    visited,
                    direct_deps,
                    depth + 1,
                    truncated,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_simple_dependency_tree() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["requests".to_string()]);
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.direct_dependencies()[0].as_str(), "requests");

        // requests should have urllib3 as transitive dependency
        let trans_deps = graph.transitive_dependencies();
        assert_eq!(trans_deps.len(), 1);
        let requests_name = PackageName::new("requests".to_string()).unwrap();
        assert!(trans_deps.contains_key(&requests_name));
        assert_eq!(trans_deps[&requests_name].len(), 1);
        assert_eq!(trans_deps[&requests_name][0].as_str(), "urllib3");

        // No chain exceeded the recursion depth guard
        assert!(truncated.is_empty());
    }

    #[test]
    fn test_analyze_no_transitive_dependencies() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["simple-lib".to_string()]);
        dependency_map.insert("simple-lib".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }

    #[test]
    fn test_analyze_multiple_direct_dependencies() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert(
            "myproject".to_string(),
            vec!["requests".to_string(), "numpy".to_string()],
        );
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);
        dependency_map.insert("numpy".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 2);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    #[test]
    fn test_collect_transitive_deps_cycle_detection() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert("pkg-a".to_string(), vec!["pkg-b".to_string()]);
        dependency_map.insert("pkg-b".to_string(), vec!["pkg-a".to_string()]); // Cycle

        let mut trans_deps = Vec::new();
        let mut visited = HashSet::new();
        let direct_deps = HashSet::new();
        let mut truncated = Vec::new();

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-a",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
            0, // Start with depth 0
            &mut truncated,
        );

        // Should not infinite loop, visited set prevents cycles
        assert!(visited.contains("pkg-a"));
        assert!(visited.contains("pkg-b"));
        assert!(truncated.is_empty());
    }

    #[test]
    fn test_collect_transitive_deps_excludes_direct_deps() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert(
            "pkg-a".to_string(),
            vec!["pkg-b".to_string(), "pkg-c".to_string()],
        );

        let mut trans_deps = Vec::new();
        let mut visited = HashSet::new();
        let mut direct_deps = HashSet::new();
        direct_deps.insert("pkg-c".to_string()); // pkg-c is direct, should not be in transitive
        let mut truncated = Vec::new();

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-a",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
            0, // Start with depth 0
            &mut truncated,
        );

        assert!(trans_deps.contains(&"pkg-b".to_string()));
        assert!(!trans_deps.contains(&"pkg-c".to_string()));
        assert!(truncated.is_empty());
    }

    #[test]
    fn test_analyze_empty_project() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 0);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }

    #[test]
    fn test_analyze_builds_edge_map_for_multi_hop_paths() {
        // project -> a -> b -> c (three hops)
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["a".to_string()]);
        dependency_map.insert("a".to_string(), vec!["b".to_string()]);
        dependency_map.insert("b".to_string(), vec!["c".to_string()]);
        dependency_map.insert("c".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        let target = PackageName::new("c".to_string()).unwrap();
        let paths = graph.find_paths_to(&target);

        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0],
            vec![
                PackageName::new("a".to_string()).unwrap(),
                PackageName::new("b".to_string()).unwrap(),
                PackageName::new("c".to_string()).unwrap(),
            ]
        );
    }

    #[test]
    fn test_analyze_excludes_project_root_from_package_edges() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["requests".to_string()]);
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        let target = PackageName::new("urllib3".to_string()).unwrap();
        let paths = graph.find_paths_to(&target);

        assert_eq!(
            paths,
            vec![vec![
                PackageName::new("requests".to_string()).unwrap(),
                PackageName::new("urllib3".to_string()).unwrap(),
            ]]
        );
        for path in &paths {
            assert_ne!(path[0].as_str(), "myproject");
        }
    }

    #[test]
    fn test_analyze_finds_multiple_paths_via_diamond() {
        // myproject -> a, b; a -> shared -> target; b -> shared -> target
        let mut dependency_map = HashMap::new();
        dependency_map.insert(
            "myproject".to_string(),
            vec!["a".to_string(), "b".to_string()],
        );
        dependency_map.insert("a".to_string(), vec!["shared".to_string()]);
        dependency_map.insert("b".to_string(), vec!["shared".to_string()]);
        dependency_map.insert("shared".to_string(), vec!["target".to_string()]);
        dependency_map.insert("target".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, _truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();
        let paths = graph.find_paths_to(&PackageName::new("target".to_string()).unwrap());

        assert_eq!(paths.len(), 2);
        for p in &paths {
            assert_eq!(p.len(), 3);
            assert_eq!(p[2].as_str(), "target");
            assert_eq!(p[1].as_str(), "shared");
        }
    }

    /// Builds a linear chain `project -> pkg-0 -> pkg-1 -> ... -> pkg-{len-1}`.
    fn make_linear_chain(len: usize) -> HashMap<String, Vec<String>> {
        let mut map = HashMap::new();
        map.insert("myproject".to_string(), vec!["pkg-0".to_string()]);
        for i in 0..len {
            let next = if i + 1 < len {
                vec![format!("pkg-{}", i + 1)]
            } else {
                vec![]
            };
            map.insert(format!("pkg-{}", i), next);
        }
        map
    }

    #[test]
    fn test_collect_transitive_deps_records_truncation_beyond_max_depth() {
        // Chain deeper than MAX_RECURSION_DEPTH (100) must be reported as truncated.
        let dependency_map = make_linear_chain(150);

        let mut trans_deps = Vec::new();
        let mut visited = HashSet::new();
        let direct_deps = HashSet::new();
        let mut truncated = Vec::new();

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-0",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
            0,
            &mut truncated,
        );

        assert_eq!(truncated.len(), 1);
        assert_eq!(
            truncated[0],
            TruncatedChainRecord {
                package_name: format!("pkg-{}", DependencyAnalyzer::MAX_RECURSION_DEPTH),
                max_depth: DependencyAnalyzer::MAX_RECURSION_DEPTH,
            }
        );
    }

    #[test]
    fn test_collect_transitive_deps_no_truncation_within_max_depth() {
        // A chain shorter than MAX_RECURSION_DEPTH must not be reported as truncated.
        let dependency_map = make_linear_chain(10);

        let mut trans_deps = Vec::new();
        let mut visited = HashSet::new();
        let direct_deps = HashSet::new();
        let mut truncated = Vec::new();

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-0",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
            0,
            &mut truncated,
        );

        assert!(truncated.is_empty());
    }

    #[test]
    fn test_analyze_returns_truncated_chain_record_for_deep_dependency_chain() {
        let dependency_map = make_linear_chain(150);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (graph, truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(truncated.len(), 1);
        assert_eq!(
            truncated[0].package_name,
            format!("pkg-{}", DependencyAnalyzer::MAX_RECURSION_DEPTH)
        );
        assert_eq!(
            truncated[0].max_depth,
            DependencyAnalyzer::MAX_RECURSION_DEPTH
        );
    }

    #[test]
    fn test_analyze_returns_empty_truncated_chains_for_shallow_dependency_chain() {
        let dependency_map = make_linear_chain(10);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let (_graph, truncated) =
            DependencyAnalyzer::analyze(&project_name, &dependency_map).unwrap();

        assert!(truncated.is_empty());
    }
}
