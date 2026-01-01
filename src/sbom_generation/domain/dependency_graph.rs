use super::{Package, PackageName};
use std::collections::HashMap;

/// DependencyGraph aggregate representing the complete dependency structure
#[derive(Debug, Clone)]
pub struct DependencyGraph {
    all_packages: Vec<Package>,
    direct_dependencies: Vec<PackageName>,
    transitive_dependencies: HashMap<PackageName, Vec<PackageName>>,
}

impl DependencyGraph {
    pub fn new(
        all_packages: Vec<Package>,
        direct_dependencies: Vec<PackageName>,
        transitive_dependencies: HashMap<PackageName, Vec<PackageName>>,
    ) -> Self {
        Self {
            all_packages,
            direct_dependencies,
            transitive_dependencies,
        }
    }

    pub fn all_packages(&self) -> &[Package] {
        &self.all_packages
    }

    pub fn direct_dependencies(&self) -> &[PackageName] {
        &self.direct_dependencies
    }

    pub fn transitive_dependencies(&self) -> &HashMap<PackageName, Vec<PackageName>> {
        &self.transitive_dependencies
    }

    pub fn total_package_count(&self) -> usize {
        self.all_packages.len()
    }

    pub fn direct_dependency_count(&self) -> usize {
        self.direct_dependencies.len()
    }

    pub fn transitive_dependency_count(&self) -> usize {
        self.transitive_dependencies
            .values()
            .map(|v| v.len())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_graph_new() {
        let pkg1 = Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap();
        let pkg2 = Package::new("pkg2".to_string(), "2.0.0".to_string()).unwrap();

        let all_packages = vec![pkg1.clone(), pkg2.clone()];
        let direct_deps = vec![PackageName::new("pkg1".to_string()).unwrap()];
        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("pkg1".to_string()).unwrap(),
            vec![PackageName::new("pkg2".to_string()).unwrap()],
        );

        let graph = DependencyGraph::new(all_packages, direct_deps, transitive);

        assert_eq!(graph.total_package_count(), 2);
        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    #[test]
    fn test_dependency_graph_empty() {
        let graph = DependencyGraph::new(vec![], vec![], HashMap::new());

        assert_eq!(graph.total_package_count(), 0);
        assert_eq!(graph.direct_dependency_count(), 0);
        assert_eq!(graph.transitive_dependency_count(), 0);
    }
}
