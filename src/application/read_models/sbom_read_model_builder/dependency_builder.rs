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
