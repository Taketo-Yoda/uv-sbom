use super::super::component_view::ComponentView;
use super::super::dependency_view::DependencyView;
use crate::sbom_generation::domain::DependencyGraph;
use std::collections::HashMap;

pub(super) fn build_dependencies(
    graph: &DependencyGraph,
    components: &[ComponentView],
) -> DependencyView {
    // Create a lookup map from package name to bom-ref
    let name_to_bom_ref: HashMap<&str, &str> = components
        .iter()
        .map(|c| (c.name.as_str(), c.bom_ref.as_str()))
        .collect();

    // Map direct dependencies to bom-refs
    let direct: Vec<String> = graph
        .direct_dependencies()
        .iter()
        .filter_map(|dep| name_to_bom_ref.get(dep.as_str()).map(|s| s.to_string()))
        .collect();

    // Build transitive dependency map
    let transitive: HashMap<String, Vec<String>> = graph
        .transitive_dependencies()
        .iter()
        .filter_map(|(parent, children)| {
            let parent_bom_ref = name_to_bom_ref.get(parent.as_str())?;
            let child_bom_refs: Vec<String> = children
                .iter()
                .filter_map(|child| name_to_bom_ref.get(child.as_str()).map(|s| s.to_string()))
                .collect();
            if child_bom_refs.is_empty() {
                None
            } else {
                Some((parent_bom_ref.to_string(), child_bom_refs))
            }
        })
        .collect();

    DependencyView { direct, transitive }
}

#[cfg(test)]
mod tests {
    use super::super::component_builder;
    use super::super::test_helpers as th;
    use super::*;
    use crate::sbom_generation::domain::{DependencyGraph, PackageName};
    use std::collections::HashMap;

    #[test]
    fn test_build_dependencies_maps_direct_to_bom_refs() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
        ];
        let components = component_builder::build_components(&packages, None);

        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("urllib3".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new(), HashMap::new());

        let deps = build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 2);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
        assert!(deps.direct.contains(&"urllib3-2.0.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_builds_transitive_map() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
            th::package("certifi", "2023.7.22"),
        ];
        let components = component_builder::build_components(&packages, None);

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![
                PackageName::new("urllib3".to_string()).unwrap(),
                PackageName::new("certifi".to_string()).unwrap(),
            ],
        );
        let graph = DependencyGraph::new(direct_deps, transitive, HashMap::new());

        let deps = build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 1);
        assert!(deps.transitive.contains_key("requests-2.31.0"));
        let requests_deps = deps.transitive.get("requests-2.31.0").unwrap();
        assert_eq!(requests_deps.len(), 2);
        assert!(requests_deps.contains(&"urllib3-2.0.0".to_string()));
        assert!(requests_deps.contains(&"certifi-2023.7.22".to_string()));
    }

    #[test]
    fn test_build_dependencies_filters_unknown_packages() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        // unknown-pkg is not in components
        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("unknown-pkg".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new(), HashMap::new());

        let deps = build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 1);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_empty_graph() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);
        let graph = DependencyGraph::new(vec![], HashMap::new(), HashMap::new());

        let deps = build_dependencies(&graph, &components);

        assert!(deps.direct.is_empty());
        assert!(deps.transitive.is_empty());
    }
}
