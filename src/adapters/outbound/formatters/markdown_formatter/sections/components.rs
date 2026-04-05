use crate::application::read_models::ComponentView;
use crate::i18n::Messages;
use std::collections::HashSet;

/// Renders the component inventory section into `output`.
///
/// Lists all components in a Markdown table with package name, version, license,
/// and description columns. Package names are hyperlinked when `verified_packages`
/// is provided and the package is present in the set.
pub(in super::super) fn render(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    components: &[ComponentView],
) {
    output.push_str(messages.section_component_inventory);
    output.push_str("\n\n");
    output.push_str(messages.desc_sbom_report);
    output.push_str("\n\n");
    output.push_str(&super::super::table::table_header(messages));
    output.push_str(&super::super::table::table_separator(messages));

    for component in components {
        let license = component
            .license
            .as_ref()
            .map(|l| l.spdx_id.as_deref().unwrap_or(l.name.as_str()))
            .unwrap_or("N/A");
        let description = component.description.as_deref().unwrap_or("");

        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            super::super::links::format_package_name(&component.name, verified_packages),
            super::super::table::escape_markdown_table_cell(&component.version),
            super::super::table::escape_markdown_table_cell(license),
            super::super::table::escape_markdown_table_cell(description)
        ));
    }
    output.push('\n');
}
