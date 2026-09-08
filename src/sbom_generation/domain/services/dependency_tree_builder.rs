use crate::sbom_generation::domain::dependency_graph::DependencyGraph;
use crate::sbom_generation::domain::package::PackageName;
use std::collections::HashSet;

/// One node in a dependency tree. Mirrors graph shape only — no version,
/// license, or hash metadata (see #781 for version enrichment).
#[allow(dead_code)] // WIRE(#781): remove when DependencyTreeBuilder is wired into GenerateSbomUseCase
#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    /// Package name.
    pub name: String,
    /// Immediate children expanded within the depth limit.
    pub children: Vec<TreeNode>,
    /// `true` when this node has children in the graph that were not
    /// expanded because `max_depth` was reached. Never set for branches
    /// stopped by cycle detection — those subtrees are genuinely complete
    /// along that path.
    pub truncated: bool,
}

/// Builds depth-limited, cycle-safe dependency trees from a `DependencyGraph`.
#[allow(dead_code)] // WIRE(#781): remove when DependencyTreeBuilder is wired into GenerateSbomUseCase
pub struct DependencyTreeBuilder;

impl DependencyTreeBuilder {
    /// Builds one root `TreeNode` per direct dependency.
    ///
    /// `max_depth` counts levels *below* each root: `0` yields roots only,
    /// `1` yields roots plus their immediate children. Roots are returned in
    /// `direct_dependencies()` order; children in `package_edges` order.
    #[allow(dead_code)] // WIRE(#781): remove when DependencyTreeBuilder is wired into GenerateSbomUseCase
    pub fn build(graph: &DependencyGraph, max_depth: usize) -> Vec<TreeNode> {
        graph
            .direct_dependencies()
            .iter()
            .map(|root| {
                let mut visited = HashSet::new();
                visited.insert(root.clone());
                build_node(graph, root, max_depth, &mut visited)
            })
            .collect()
    }
}

#[allow(dead_code)] // WIRE(#781): remove when DependencyTreeBuilder is wired into GenerateSbomUseCase
fn build_node(
    graph: &DependencyGraph,
    pkg: &PackageName,
    remaining_depth: usize,
    visited: &mut HashSet<PackageName>,
) -> TreeNode {
    let children_names = graph.children_of(pkg).unwrap_or(&[]);

    if remaining_depth == 0 {
        return TreeNode {
            name: pkg.as_str().to_string(),
            children: Vec::new(),
            truncated: !children_names.is_empty(),
        };
    }

    let mut children = Vec::new();
    for child in children_names {
        if visited.contains(child) {
            continue;
        }
        visited.insert(child.clone());
        children.push(build_node(graph, child, remaining_depth - 1, visited));
        visited.remove(child);
    }

    TreeNode {
        name: pkg.as_str().to_string(),
        children,
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn pkg(name: &str) -> PackageName {
        PackageName::new(name.to_string()).unwrap()
    }

    fn make_graph(direct: Vec<&str>, edges: Vec<(&str, Vec<&str>)>) -> DependencyGraph {
        let direct_deps = direct.into_iter().map(pkg).collect();
        let package_edges: HashMap<PackageName, Vec<PackageName>> = edges
            .into_iter()
            .map(|(parent, children)| (pkg(parent), children.into_iter().map(pkg).collect()))
            .collect();
        DependencyGraph::new(direct_deps, HashMap::new(), package_edges)
    }

    fn node(name: &str, children: Vec<TreeNode>, truncated: bool) -> TreeNode {
        TreeNode {
            name: name.to_string(),
            children,
            truncated,
        }
    }

    #[test]
    fn test_build_empty_graph() {
        let graph = make_graph(vec![], vec![]);
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_build_simple_tree() {
        let graph = make_graph(
            vec!["requests"],
            vec![("requests", vec!["urllib3"]), ("urllib3", vec!["certifi"])],
        );
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert_eq!(
            tree,
            vec![node(
                "requests",
                vec![node("urllib3", vec![node("certifi", vec![], false)], false)],
                false
            )]
        );
    }

    #[test]
    fn test_build_diamond_dependency_not_deduplicated() {
        // requests -> urllib3, httpx -> urllib3
        let graph = make_graph(
            vec!["requests", "httpx"],
            vec![("requests", vec!["urllib3"]), ("httpx", vec!["urllib3"])],
        );
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert_eq!(
            tree,
            vec![
                node("requests", vec![node("urllib3", vec![], false)], false),
                node("httpx", vec![node("urllib3", vec![], false)], false),
            ]
        );
    }

    #[test]
    fn test_build_max_depth_zero_root_with_children_is_truncated() {
        let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
        let tree = DependencyTreeBuilder::build(&graph, 0);
        assert_eq!(tree, vec![node("requests", vec![], true)]);
    }

    #[test]
    fn test_build_max_depth_zero_leaf_root_is_not_truncated() {
        let graph = make_graph(vec!["requests"], vec![]);
        let tree = DependencyTreeBuilder::build(&graph, 0);
        assert_eq!(tree, vec![node("requests", vec![], false)]);
    }

    #[test]
    fn test_build_depth_truncation_mid_chain() {
        // a -> b -> c -> d, max_depth=1 keeps a and b, truncates b's children
        let graph = make_graph(
            vec!["a"],
            vec![("a", vec!["b"]), ("b", vec!["c"]), ("c", vec!["d"])],
        );
        let tree = DependencyTreeBuilder::build(&graph, 1);
        assert_eq!(tree, vec![node("a", vec![node("b", vec![], true)], false)]);
    }

    #[test]
    fn test_build_cycle_safe_direct_self_cycle() {
        // a -> a (self cycle)
        let graph = make_graph(vec!["a"], vec![("a", vec!["a"])]);
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert_eq!(tree, vec![node("a", vec![], false)]);
    }

    #[test]
    fn test_build_cycle_safe_indirect_cycle() {
        // a -> b -> a
        let graph = make_graph(vec!["a"], vec![("a", vec!["b"]), ("b", vec!["a"])]);
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert_eq!(tree, vec![node("a", vec![node("b", vec![], false)], false)]);
    }

    #[test]
    fn test_build_direct_dependency_with_no_edges_is_leaf() {
        let graph = make_graph(vec!["requests"], vec![]);
        let tree = DependencyTreeBuilder::build(&graph, 5);
        assert_eq!(tree, vec![node("requests", vec![], false)]);
    }
}
