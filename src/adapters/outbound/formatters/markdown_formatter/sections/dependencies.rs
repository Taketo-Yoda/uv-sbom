use crate::application::read_models::{ComponentView, DependencyView};
use crate::i18n::Messages;
use std::collections::{HashMap, HashSet};

fn render_component_row(
    output: &mut String,
    component: &ComponentView,
    verified_packages: Option<&HashSet<String>>,
) {
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

/// Renders the dependencies section
pub(in super::super) fn render(
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
        output.push_str(&super::super::table::table_header(messages));
        output.push_str(&super::super::table::table_separator(messages));

        for bom_ref in &deps.direct {
            if let Some(component) = component_map.get(bom_ref.as_str()) {
                render_component_row(output, component, verified_packages);
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
                output.push_str(&super::super::table::table_header(messages));
                output.push_str(&super::super::table::table_separator(messages));

                for trans_ref in trans_deps {
                    if let Some(component) = component_map.get(trans_ref.as_str()) {
                        render_component_row(output, component, verified_packages);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{ComponentView, DependencyView, LicenseView};
    use crate::i18n::Locale;

    fn make_component(bom_ref: &str, name: &str, version: &str) -> ComponentView {
        ComponentView {
            bom_ref: bom_ref.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            purl: format!("pkg:pypi/{name}@{version}"),
            license: Some(LicenseView {
                spdx_id: Some("MIT".to_string()),
                name: "MIT License".to_string(),
            }),
            description: Some(format!("{name} description")),
            sha256_hash: None,
            is_direct_dependency: true,
        }
    }

    fn call_render(locale: Locale, deps: &DependencyView, components: &[ComponentView]) -> String {
        let messages = crate::i18n::Messages::for_locale(locale);
        let mut output = String::new();
        render(messages, None, &mut output, deps, components);
        output
    }

    // --- i18n header tests ---

    #[test]
    fn test_section_headers_en() {
        let deps = DependencyView::default();
        let output = call_render(Locale::En, &deps, &[]);

        assert!(output.contains("## Direct Dependencies"));
        assert!(output.contains("## Transitive Dependencies"));
    }

    #[test]
    fn test_section_headers_ja() {
        let deps = DependencyView::default();
        let output = call_render(Locale::Ja, &deps, &[]);

        assert!(output.contains("## 直接依存パッケージ"));
        assert!(output.contains("## 間接依存パッケージ"));
    }

    // --- empty-dependency edge cases ---

    #[test]
    fn test_empty_direct_deps_shows_label() {
        let deps = DependencyView::default();
        let output = call_render(Locale::En, &deps, &[]);

        assert!(output.contains("*No direct dependencies*"));
    }

    #[test]
    fn test_empty_transitive_deps_shows_label() {
        let deps = DependencyView::default();
        let output = call_render(Locale::En, &deps, &[]);

        assert!(output.contains("*No transitive dependencies*"));
    }

    #[test]
    fn test_empty_labels_ja() {
        let deps = DependencyView::default();
        let output = call_render(Locale::Ja, &deps, &[]);

        assert!(output.contains("*直接依存パッケージなし*"));
        assert!(output.contains("*間接依存パッケージなし*"));
    }

    // --- direct dependency row rendering ---

    #[test]
    fn test_direct_dep_row_appears() {
        let component = make_component("pkg-a", "requests", "2.31.0");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());

        let output = call_render(Locale::En, &deps, &[component]);

        assert!(output.contains("requests"));
        assert!(output.contains("2.31.0"));
        assert!(output.contains("MIT"));
    }

    #[test]
    fn test_multiple_direct_deps_appear() {
        let comp_a = make_component("pkg-a", "requests", "2.31.0");
        let comp_b = make_component("pkg-b", "httpx", "0.25.0");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());
        deps.direct.push("pkg-b".to_string());

        let output = call_render(Locale::En, &deps, &[comp_a, comp_b]);

        assert!(output.contains("requests"));
        assert!(output.contains("httpx"));
    }

    #[test]
    fn test_direct_dep_no_license_shows_na() {
        let mut component = make_component("pkg-a", "no-license-pkg", "1.0.0");
        component.license = None;
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());

        let output = call_render(Locale::En, &deps, &[component]);

        assert!(output.contains("N/A"));
    }

    // --- transitive dependency row rendering ---

    #[test]
    fn test_transitive_dep_row_appears() {
        let direct = make_component("pkg-a", "requests", "2.31.0");
        let transitive = make_component("pkg-b", "urllib3", "2.0.7");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());
        deps.transitive
            .insert("pkg-a".to_string(), vec!["pkg-b".to_string()]);

        let output = call_render(Locale::En, &deps, &[direct, transitive]);

        assert!(output.contains("urllib3"));
        assert!(output.contains("2.0.7"));
    }

    #[test]
    fn test_transitive_section_header_shows_parent_name() {
        let direct = make_component("pkg-a", "requests", "2.31.0");
        let transitive = make_component("pkg-b", "urllib3", "2.0.7");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());
        deps.transitive
            .insert("pkg-a".to_string(), vec!["pkg-b".to_string()]);

        let output = call_render(Locale::En, &deps, &[direct, transitive]);

        assert!(output.contains("### Dependencies for requests"));
    }

    #[test]
    fn test_transitive_section_header_shows_parent_name_ja() {
        let direct = make_component("pkg-a", "requests", "2.31.0");
        let transitive = make_component("pkg-b", "urllib3", "2.0.7");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());
        deps.transitive
            .insert("pkg-a".to_string(), vec!["pkg-b".to_string()]);

        let output = call_render(Locale::Ja, &deps, &[direct, transitive]);

        assert!(output.contains("### requestsの依存パッケージ"));
    }

    #[test]
    fn test_direct_with_no_transitive_shows_no_transitive_label() {
        let component = make_component("pkg-a", "requests", "2.31.0");
        let mut deps = DependencyView::default();
        deps.direct.push("pkg-a".to_string());
        // transitive is empty

        let output = call_render(Locale::En, &deps, &[component]);

        assert!(output.contains("requests"));
        assert!(output.contains("*No transitive dependencies*"));
    }
}
