use crate::sbom_generation::domain::{DependencyGraph, Package, PackageName};
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

/// DependencyAnalyzer service for analyzing transitive dependencies
///
/// This service contains pure business logic for dependency graph analysis.
/// It has no I/O dependencies and works only with domain objects.
pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    /// Analyzes dependencies and builds a DependencyGraph
    ///
    /// # Arguments
    /// * `packages` - All packages in the lockfile
    /// * `project_name` - The name of the root project
    /// * `dependency_map` - Map of package name to its dependencies
    ///
    /// # Returns
    /// A DependencyGraph containing all packages, direct dependencies, and transitive dependencies
    pub fn analyze(
        packages: Vec<Package>,
        project_name: &PackageName,
        dependency_map: &HashMap<String, Vec<String>>,
    ) -> Result<DependencyGraph> {
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

        for direct_dep in &direct_deps {
            let mut trans_deps = Vec::new();
            let mut visited = HashSet::new();

            Self::collect_transitive_deps(
                direct_dep,
                dependency_map,
                &mut trans_deps,
                &mut visited,
                &direct_deps_set,
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

        Ok(DependencyGraph::new(
            packages,
            direct_deps_names,
            transitive_dependencies,
        ))
    }

    /// Recursively collects transitive dependencies for a package
    ///
    /// This is a pure algorithm with no I/O operations.
    ///
    /// # Arguments
    /// * `package_name` - The package to analyze
    /// * `dependency_map` - Map of package name to its dependencies
    /// * `trans_deps` - Accumulated transitive dependencies
    /// * `visited` - Set of already visited packages (cycle detection)
    /// * `direct_deps` - Set of direct dependencies (to exclude from transitive)
    fn collect_transitive_deps(
        package_name: &str,
        dependency_map: &HashMap<String, Vec<String>>,
        trans_deps: &mut Vec<String>,
        visited: &mut HashSet<String>,
        direct_deps: &HashSet<String>,
    ) {
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
                // Recursively collect transitive dependencies
                Self::collect_transitive_deps(dep, dependency_map, trans_deps, visited, direct_deps);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_package(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    #[test]
    fn test_analyze_simple_dependency_tree() {
        let packages = vec![
            create_test_package("myproject", "1.0.0"),
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "1.26.0"),
        ];

        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["requests".to_string()]);
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let graph = DependencyAnalyzer::analyze(packages, &project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.direct_dependencies()[0].as_str(), "requests");

        // requests should have urllib3 as transitive dependency
        let trans_deps = graph.transitive_dependencies();
        assert_eq!(trans_deps.len(), 1);
        let requests_name = PackageName::new("requests".to_string()).unwrap();
        assert!(trans_deps.contains_key(&requests_name));
        assert_eq!(trans_deps[&requests_name].len(), 1);
        assert_eq!(trans_deps[&requests_name][0].as_str(), "urllib3");
    }

    #[test]
    fn test_analyze_no_transitive_dependencies() {
        let packages = vec![
            create_test_package("myproject", "1.0.0"),
            create_test_package("simple-lib", "1.0.0"),
        ];

        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec!["simple-lib".to_string()]);
        dependency_map.insert("simple-lib".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let graph = DependencyAnalyzer::analyze(packages, &project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }

    #[test]
    fn test_analyze_multiple_direct_dependencies() {
        let packages = vec![
            create_test_package("myproject", "1.0.0"),
            create_test_package("requests", "2.31.0"),
            create_test_package("numpy", "1.24.0"),
            create_test_package("urllib3", "1.26.0"),
        ];

        let mut dependency_map = HashMap::new();
        dependency_map.insert(
            "myproject".to_string(),
            vec!["requests".to_string(), "numpy".to_string()],
        );
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);
        dependency_map.insert("numpy".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let graph = DependencyAnalyzer::analyze(packages, &project_name, &dependency_map).unwrap();

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

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-a",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
        );

        // Should not infinite loop, visited set prevents cycles
        assert!(visited.contains("pkg-a"));
        assert!(visited.contains("pkg-b"));
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

        DependencyAnalyzer::collect_transitive_deps(
            "pkg-a",
            &dependency_map,
            &mut trans_deps,
            &mut visited,
            &direct_deps,
        );

        assert!(trans_deps.contains(&"pkg-b".to_string()));
        assert!(!trans_deps.contains(&"pkg-c".to_string()));
    }

    #[test]
    fn test_analyze_empty_project() {
        let packages = vec![create_test_package("myproject", "1.0.0")];
        let mut dependency_map = HashMap::new();
        dependency_map.insert("myproject".to_string(), vec![]);

        let project_name = PackageName::new("myproject".to_string()).unwrap();
        let graph = DependencyAnalyzer::analyze(packages, &project_name, &dependency_map).unwrap();

        assert_eq!(graph.direct_dependency_count(), 0);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }
}
