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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::LicenseView;
    use crate::i18n::{Locale, Messages};

    fn make_component(
        name: &str,
        version: &str,
        spdx_id: Option<&str>,
        license_name: &str,
        description: Option<&str>,
    ) -> ComponentView {
        ComponentView {
            bom_ref: format!("pkg:pypi/{}@{}", name, version),
            name: name.to_string(),
            version: version.to_string(),
            purl: format!("pkg:pypi/{}@{}", name, version),
            license: Some(LicenseView {
                spdx_id: spdx_id.map(|s| s.to_string()),
                name: license_name.to_string(),
            }),
            description: description.map(|s| s.to_string()),
            sha256_hash: None,
            is_direct_dependency: true,
        }
    }

    // ============================================================
    // License fallback logic
    // ============================================================

    #[test]
    fn test_license_spdx_id_is_used_when_present() {
        let msgs = Messages::for_locale(Locale::En);
        let component = make_component(
            "requests",
            "2.31.0",
            Some("Apache-2.0"),
            "Apache License 2.0",
            None,
        );
        let mut output = String::new();
        render(msgs, None, &mut output, &[component]);
        assert!(output.contains("Apache-2.0"));
        assert!(!output.contains("Apache License 2.0"));
    }

    #[test]
    fn test_license_name_fallback_when_spdx_id_is_none() {
        let msgs = Messages::for_locale(Locale::En);
        let component = make_component("requests", "2.31.0", None, "Apache License 2.0", None);
        let mut output = String::new();
        render(msgs, None, &mut output, &[component]);
        assert!(output.contains("Apache License 2.0"));
    }

    #[test]
    fn test_license_na_fallback_when_license_is_none() {
        let msgs = Messages::for_locale(Locale::En);
        let component = ComponentView {
            bom_ref: "pkg:pypi/no-license@1.0.0".to_string(),
            name: "no-license".to_string(),
            version: "1.0.0".to_string(),
            purl: "pkg:pypi/no-license@1.0.0".to_string(),
            license: None,
            description: None,
            sha256_hash: None,
            is_direct_dependency: true,
        };
        let mut output = String::new();
        render(msgs, None, &mut output, &[component]);
        assert!(output.contains("N/A"));
    }

    // ============================================================
    // i18n column headers
    // ============================================================

    #[test]
    fn test_en_locale_column_headers() {
        let msgs = Messages::for_locale(Locale::En);
        let mut output = String::new();
        render(msgs, None, &mut output, &[]);
        assert!(output.contains("| Package | Version | License | Description |"));
    }

    #[test]
    fn test_ja_locale_column_headers() {
        let msgs = Messages::for_locale(Locale::Ja);
        let mut output = String::new();
        render(msgs, None, &mut output, &[]);
        assert!(output.contains("| パッケージ | バージョン | ライセンス | 説明 |"));
    }

    // ============================================================
    // Verified packages (link vs plain text)
    // ============================================================

    #[test]
    fn test_verified_package_renders_pypi_link() {
        let msgs = Messages::for_locale(Locale::En);
        let component = make_component("requests", "2.31.0", Some("MIT"), "MIT License", None);
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let mut output = String::new();
        render(msgs, Some(&verified), &mut output, &[component]);
        assert!(output.contains("[requests](https://pypi.org/project/requests/)"));
    }

    #[test]
    fn test_unverified_package_renders_plain_text() {
        let msgs = Messages::for_locale(Locale::En);
        let component = make_component("requests", "2.31.0", Some("MIT"), "MIT License", None);
        let verified = HashSet::new();
        let mut output = String::new();
        render(msgs, Some(&verified), &mut output, &[component]);
        assert!(!output.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(output.contains("| requests |"));
    }

    #[test]
    fn test_no_verification_always_renders_pypi_link() {
        let msgs = Messages::for_locale(Locale::En);
        let component = make_component("requests", "2.31.0", Some("MIT"), "MIT License", None);
        let mut output = String::new();
        render(msgs, None, &mut output, &[component]);
        assert!(output.contains("[requests](https://pypi.org/project/requests/)"));
    }
}
