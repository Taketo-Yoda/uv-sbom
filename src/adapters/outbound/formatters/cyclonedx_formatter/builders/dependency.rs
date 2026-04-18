use crate::application::read_models::DependencyView;

use super::super::schema::Dependency;

/// Build a list of CycloneDX [`Dependency`] entries from a [`DependencyView`].
///
/// Direct dependencies are listed first, each with their transitive children as
/// `depends_on`. Packages that appear only as transitives (not in
/// `dep_view.direct`) are appended afterward with their own `depends_on` list.
pub(in super::super) fn build(dep_view: &DependencyView) -> Vec<Dependency> {
    let mut dependencies = Vec::new();

    // Add direct dependencies
    for direct_ref in &dep_view.direct {
        let depends_on = dep_view
            .transitive
            .get(direct_ref)
            .cloned()
            .unwrap_or_default();
        dependencies.push(Dependency {
            bom_ref: direct_ref.clone(),
            depends_on,
        });
    }

    // Add transitive dependencies that are not direct
    for (parent_ref, children) in &dep_view.transitive {
        if !dep_view.direct.contains(parent_ref) {
            dependencies.push(Dependency {
                bom_ref: parent_ref.clone(),
                depends_on: children.clone(),
            });
        }
    }

    dependencies
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_build_direct_dependency_with_transitive_children() {
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );

        let dep_view = DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        };

        let result = build(&dep_view);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bom_ref, "pkg:pypi/requests@2.31.0");
        assert_eq!(result[0].depends_on, vec!["pkg:pypi/urllib3@1.26.0"]);
    }

    #[test]
    fn test_build_transitive_only_dependency_is_included() {
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );
        transitive.insert(
            "pkg:pypi/urllib3@1.26.0".to_string(),
            vec!["pkg:pypi/certifi@2023.0.0".to_string()],
        );

        let dep_view = DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        };

        let result = build(&dep_view);

        assert_eq!(result.len(), 2);
        let refs: Vec<&str> = result.iter().map(|d| d.bom_ref.as_str()).collect();
        assert!(refs.contains(&"pkg:pypi/requests@2.31.0"));
        assert!(refs.contains(&"pkg:pypi/urllib3@1.26.0"));
    }

    #[test]
    fn test_build_direct_dependency_without_children() {
        let dep_view = DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive: HashMap::new(),
        };

        let result = build(&dep_view);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bom_ref, "pkg:pypi/requests@2.31.0");
        assert!(result[0].depends_on.is_empty());
    }
}
