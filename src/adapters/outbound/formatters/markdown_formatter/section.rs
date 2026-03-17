use crate::application::read_models::{ComponentView, DependencyView};
use crate::i18n::Messages;
use std::collections::{HashMap, HashSet};

/// Renders the header section
pub(super) fn render_header(messages: &'static Messages, output: &mut String) {
    output.push_str(messages.section_sbom_title);
    output.push_str("\n\n");
}

/// Renders the components section
pub(super) fn render_components(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    components: &[ComponentView],
) {
    output.push_str(messages.section_component_inventory);
    output.push_str("\n\n");
    output.push_str(messages.desc_sbom_report);
    output.push_str("\n\n");
    output.push_str(&super::table::table_header(messages));
    output.push_str(&super::table::table_separator(messages));

    for component in components {
        let license = component
            .license
            .as_ref()
            .map(|l| l.name.as_str())
            .unwrap_or("N/A");
        let description = component.description.as_deref().unwrap_or("");

        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            super::links::format_package_name(&component.name, verified_packages),
            super::table::escape_markdown_table_cell(&component.version),
            super::table::escape_markdown_table_cell(license),
            super::table::escape_markdown_table_cell(description)
        ));
    }
    output.push('\n');
}

/// Renders the dependencies section
pub(super) fn render_dependencies(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    deps: &DependencyView,
    components: &[ComponentView],
) {
    // Create component lookup map by bom_ref
    let component_map: HashMap<&str, &ComponentView> =
        components.iter().map(|c| (c.bom_ref.as_str(), c)).collect();

    // Direct Dependencies section
    output.push_str(messages.section_direct_deps);
    output.push_str("\n\n");
    output.push_str(messages.desc_direct_deps);
    output.push_str("\n\n");

    if !deps.direct.is_empty() {
        output.push_str(&super::table::table_header(messages));
        output.push_str(&super::table::table_separator(messages));

        for bom_ref in &deps.direct {
            if let Some(component) = component_map.get(bom_ref.as_str()) {
                let license = component
                    .license
                    .as_ref()
                    .map(|l| l.name.as_str())
                    .unwrap_or("N/A");
                let description = component.description.as_deref().unwrap_or("");

                output.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    super::links::format_package_name(&component.name, verified_packages),
                    super::table::escape_markdown_table_cell(&component.version),
                    super::table::escape_markdown_table_cell(license),
                    super::table::escape_markdown_table_cell(description)
                ));
            }
        }
        output.push('\n');
    } else {
        output.push_str(messages.label_no_direct_deps);
        output.push_str("\n\n");
    }

    // Transitive Dependencies section
    output.push_str(messages.section_transitive_deps);
    output.push_str("\n\n");
    output.push_str(messages.desc_transitive_deps);
    output.push_str("\n\n");

    if !deps.transitive.is_empty() {
        for direct_ref in &deps.direct {
            if let Some(trans_deps) = deps.transitive.get(direct_ref) {
                if trans_deps.is_empty() {
                    continue;
                }

                // Get direct dependency name for header
                let parent_name = component_map
                    .get(direct_ref.as_str())
                    .map(|c| c.name.as_str())
                    .unwrap_or(direct_ref);

                output.push_str(&Messages::format(messages.deps_for_header, &[parent_name]));
                output.push_str("\n\n");
                output.push_str(&super::table::table_header(messages));
                output.push_str(&super::table::table_separator(messages));

                for trans_ref in trans_deps {
                    if let Some(component) = component_map.get(trans_ref.as_str()) {
                        let license = component
                            .license
                            .as_ref()
                            .map(|l| l.name.as_str())
                            .unwrap_or("N/A");
                        let description = component.description.as_deref().unwrap_or("");

                        output.push_str(&format!(
                            "| {} | {} | {} | {} |\n",
                            super::links::format_package_name(&component.name, verified_packages),
                            super::table::escape_markdown_table_cell(&component.version),
                            super::table::escape_markdown_table_cell(license),
                            super::table::escape_markdown_table_cell(description)
                        ));
                    }
                }
                output.push('\n');
            }
        }
    } else {
        output.push_str(messages.label_no_transitive_deps);
        output.push_str("\n\n");
    }
}
