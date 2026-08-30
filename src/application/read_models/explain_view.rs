//! Read model for the `--explain <PACKAGE>` dependency-path query.
//!
//! All values are pre-converted to `String` so formatters need no domain access.

/// View representation of a `--explain` dependency-path query result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainView {
    /// The package name exactly as the user supplied it on the CLI.
    pub target_package: String,
    /// Whether the package exists anywhere in the analyzed dependency tree.
    pub found: bool,
    /// Whether the package is a direct dependency of the project.
    ///
    /// A package can be both direct and reachable transitively via another
    /// direct dependency; in that case `is_direct` is `true` and `paths` is
    /// non-empty at the same time.
    pub is_direct: bool,
    /// Every path from a direct dependency to the target, ordered
    /// `[direct_dep, ..., target]`. Empty when the target is a direct
    /// dependency with no other path (one-hop paths are not shown, per
    /// `DependencyGraph::find_paths_to`) or when the target was not found.
    pub paths: Vec<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(found: bool, is_direct: bool, paths: Vec<Vec<String>>) -> ExplainView {
        ExplainView {
            target_package: "requests".to_string(),
            found,
            is_direct,
            paths,
        }
    }

    #[test]
    fn test_view_clone_and_eq() {
        let a = make_view(
            true,
            false,
            vec![vec!["a".to_string(), "requests".to_string()]],
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_not_found_view() {
        let view = make_view(false, false, vec![]);
        assert!(!view.found);
        assert!(!view.is_direct);
        assert!(view.paths.is_empty());
    }

    #[test]
    fn test_direct_dependency_view() {
        let view = make_view(true, true, vec![]);
        assert!(view.found);
        assert!(view.is_direct);
        assert!(view.paths.is_empty());
    }
}
