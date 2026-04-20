use super::PackageName;
use std::collections::{HashMap, HashSet, VecDeque};

/// DependencyGraph aggregate representing the complete dependency structure
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    direct_dependencies: Vec<PackageName>,
    transitive_dependencies: HashMap<PackageName, Vec<PackageName>>,
}

impl DependencyGraph {
    pub fn new(
        direct_dependencies: Vec<PackageName>,
        transitive_dependencies: HashMap<PackageName, Vec<PackageName>>,
    ) -> Self {
        Self {
            direct_dependencies,
            transitive_dependencies,
        }
    }

    pub fn direct_dependencies(&self) -> &[PackageName] {
        &self.direct_dependencies
    }

    pub fn transitive_dependencies(&self) -> &HashMap<PackageName, Vec<PackageName>> {
        &self.transitive_dependencies
    }

    pub fn direct_dependency_count(&self) -> usize {
        self.direct_dependencies.len()
    }

    pub fn transitive_dependency_count(&self) -> usize {
        self.transitive_dependencies.values().map(|v| v.len()).sum()
    }

    /// Returns all paths from any direct dependency to `target`.
    /// Each path is ordered `[direct_dep, ..., target]`.
    /// Returns an empty Vec if `target` is itself a direct dependency (one-hop not shown).
    /// Uses BFS with per-path visited tracking to handle cyclic graphs safely.
    pub fn find_paths_to(&self, target: &PackageName) -> Vec<Vec<PackageName>> {
        let mut results: Vec<Vec<PackageName>> = Vec::new();
        let mut queue: VecDeque<(PackageName, Vec<PackageName>, HashSet<PackageName>)> =
            VecDeque::new();

        for direct in &self.direct_dependencies {
            if direct == target {
                continue;
            }
            let path = vec![direct.clone()];
            let mut visited = HashSet::new();
            visited.insert(direct.clone());
            queue.push_back((direct.clone(), path, visited));
        }

        while let Some((current, path, visited)) = queue.pop_front() {
            let Some(children) = self.transitive_dependencies.get(&current) else {
                continue;
            };

            for child in children {
                if visited.contains(child) {
                    continue;
                }
                let mut new_path = path.clone();
                new_path.push(child.clone());

                if child == target {
                    results.push(new_path);
                    continue;
                }

                let mut new_visited = visited.clone();
                new_visited.insert(child.clone());
                queue.push_back((child.clone(), new_path, new_visited));
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name.to_string()).unwrap()
    }

    fn make_graph(
        direct: Vec<&str>,
        edges: Vec<(&str, Vec<&str>)>,
    ) -> DependencyGraph {
        let direct_deps = direct.into_iter().map(pkg).collect();
        let transitive = edges
            .into_iter()
            .map(|(parent, children)| (pkg(parent), children.into_iter().map(pkg).collect()))
            .collect();
        DependencyGraph::new(direct_deps, transitive)
    }

    #[test]
    fn test_dependency_graph_new() {
        let direct_deps = vec![PackageName::new("pkg1".to_string()).unwrap()];
        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("pkg1".to_string()).unwrap(),
            vec![PackageName::new("pkg2".to_string()).unwrap()],
        );

        let graph = DependencyGraph::new(direct_deps, transitive);

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    #[test]
    fn test_dependency_graph_empty() {
        let graph = DependencyGraph::new(vec![], HashMap::new());

        assert_eq!(graph.direct_dependency_count(), 0);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }

    #[test]
    fn test_find_paths_to_simple_transitive() {
        let graph = make_graph(
            vec!["requests"],
            vec![("requests", vec!["urllib3"])],
        );
        let paths = graph.find_paths_to(&pkg("urllib3"));
        assert_eq!(paths, vec![vec![pkg("requests"), pkg("urllib3")]]);
    }

    #[test]
    fn test_find_paths_to_deep_chain() {
        let graph = make_graph(
            vec!["a"],
            vec![("a", vec!["b"]), ("b", vec!["c"]), ("c", vec!["d"])],
        );
        let paths = graph.find_paths_to(&pkg("d"));
        assert_eq!(paths, vec![vec![pkg("a"), pkg("b"), pkg("c"), pkg("d")]]);
    }

    #[test]
    fn test_find_paths_to_diamond() {
        let graph = make_graph(
            vec!["requests", "httpx"],
            vec![
                ("requests", vec!["urllib3"]),
                ("httpx", vec!["urllib3"]),
            ],
        );
        let paths = graph.find_paths_to(&pkg("urllib3"));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![pkg("requests"), pkg("urllib3")]));
        assert!(paths.contains(&vec![pkg("httpx"), pkg("urllib3")]));
    }

    #[test]
    fn test_find_paths_to_direct_dep_returns_empty() {
        let graph = make_graph(vec!["requests"], vec![]);
        let paths = graph.find_paths_to(&pkg("requests"));
        assert!(paths.is_empty());
    }

    #[test]
    fn test_find_paths_to_direct_dep_reachable_via_other() {
        // "b" is direct dep AND reachable via "a" -> "b"
        let graph = make_graph(
            vec!["a", "b"],
            vec![("a", vec!["b"])],
        );
        let paths = graph.find_paths_to(&pkg("b"));
        // trivial start from "b" is suppressed; multi-hop via "a" is returned
        assert_eq!(paths, vec![vec![pkg("a"), pkg("b")]]);
    }

    #[test]
    fn test_find_paths_to_nonexistent_target() {
        let graph = make_graph(vec!["a"], vec![("a", vec!["b"])]);
        let paths = graph.find_paths_to(&pkg("zzz"));
        assert!(paths.is_empty());
    }

    #[test]
    fn test_find_paths_to_empty_graph() {
        let graph = make_graph(vec![], vec![]);
        let paths = graph.find_paths_to(&pkg("anything"));
        assert!(paths.is_empty());
    }

    #[test]
    fn test_find_paths_to_cycle_safe() {
        // a -> b -> a (cycle), a -> target
        let graph = make_graph(
            vec!["a"],
            vec![("a", vec!["b", "target"]), ("b", vec!["a"])],
        );
        let paths = graph.find_paths_to(&pkg("target"));
        assert_eq!(paths, vec![vec![pkg("a"), pkg("target")]]);
    }

    #[test]
    fn test_find_paths_to_multiple_intermediates() {
        // a -> b -> target, a -> c -> target
        let graph = make_graph(
            vec!["a"],
            vec![
                ("a", vec!["b", "c"]),
                ("b", vec!["target"]),
                ("c", vec!["target"]),
            ],
        );
        let paths = graph.find_paths_to(&pkg("target"));
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![pkg("a"), pkg("b"), pkg("target")]));
        assert!(paths.contains(&vec![pkg("a"), pkg("c"), pkg("target")]));
    }

    #[test]
    fn test_find_paths_to_target_appears_midpath() {
        // a -> target -> x  (BFS stops at target, does not continue to x)
        let graph = make_graph(
            vec!["a"],
            vec![("a", vec!["target"]), ("target", vec!["x"])],
        );
        let paths = graph.find_paths_to(&pkg("target"));
        assert_eq!(paths, vec![vec![pkg("a"), pkg("target")]]);
    }
}
