//! Read model for the `--show-dependency-tree` visualization.
//!
//! All values are pre-converted to `String`/`Option<String>` so formatters need
//! no domain access. Unlike the domain's `TreeNode`, each node also carries a
//! resolved `version` — `DependencyGraph` has no version data, so this is
//! joined here from `EnrichedPackage` by the use case that builds this view.

/// One node in the rendered dependency tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyTreeNodeView {
    /// Package name.
    pub name: String,
    /// Resolved version, joined from the enriched package list.
    /// `None` when the package could not be found there (e.g. excluded by a
    /// filter that ran before this view was built).
    pub version: Option<String>,
    /// Immediate children expanded within the depth limit.
    pub children: Vec<DependencyTreeNodeView>,
    /// `true` when this node has children in the graph that were not
    /// expanded because the configured depth limit was reached.
    pub truncated: bool,
}

/// View representation of a `--show-dependency-tree` query result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyTreeView {
    /// One root per direct dependency, in `DependencyGraph::direct_dependencies()` order.
    pub roots: Vec<DependencyTreeNodeView>,
    /// The depth limit that was actually applied to build this tree.
    pub max_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str, version: Option<&str>) -> DependencyTreeNodeView {
        DependencyTreeNodeView {
            name: name.to_string(),
            version: version.map(str::to_string),
            children: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn test_view_clone_and_eq() {
        let a = DependencyTreeView {
            roots: vec![leaf("requests", Some("2.31.0"))],
            max_depth: 3,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_node_with_unresolved_version_is_none() {
        let node = leaf("mystery-pkg", None);
        assert!(node.version.is_none());
    }

    #[test]
    fn test_node_with_truncated_children() {
        let node = DependencyTreeNodeView {
            name: "a".to_string(),
            version: Some("1.0.0".to_string()),
            children: Vec::new(),
            truncated: true,
        };
        assert!(node.truncated);
        assert!(node.children.is_empty());
    }
}
