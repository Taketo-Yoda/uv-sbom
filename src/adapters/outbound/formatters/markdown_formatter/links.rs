use std::collections::HashSet;

use super::table;

/// Normalize package name for PyPI URL (lowercase, replace _ with -)
pub(super) fn normalize_for_pypi(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Generate a Markdown hyperlink to the package's PyPI page
pub(super) fn package_to_pypi_link(name: &str) -> String {
    let normalized = normalize_for_pypi(name);
    format!(
        "[{}](https://pypi.org/project/{}/)",
        table::escape_markdown_table_cell(name),
        normalized
    )
}

/// Generate a Markdown hyperlink for a vulnerability ID based on its prefix.
///
/// - `CVE-*` → NVD (NIST)
/// - `GHSA-*` → GitHub Advisories
/// - All others (PYSEC, RUSTSEC, etc.) → OSV.dev
pub(super) fn vulnerability_id_to_link(id: &str) -> String {
    let url = if id.starts_with("CVE-") {
        format!("https://nvd.nist.gov/vuln/detail/{}", id)
    } else if id.starts_with("GHSA-") {
        format!("https://github.com/advisories/{}", id)
    } else {
        format!("https://osv.dev/vulnerability/{}", id)
    };
    format!("[{}]({})", table::escape_markdown_table_cell(id), url)
}

/// Format a package name as a PyPI link or plain text based on verification results.
/// - If no verification was performed (verified_packages is None), always generate a link.
/// - If verification was performed, only generate a link for verified packages.
pub(super) fn format_package_name(
    name: &str,
    verified_packages: Option<&HashSet<String>>,
) -> String {
    match verified_packages {
        None => package_to_pypi_link(name),
        Some(verified) => {
            if verified.contains(name) {
                package_to_pypi_link(name)
            } else {
                table::escape_markdown_table_cell(name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::MarkdownFormatter;
    use super::*;
    use crate::application::read_models::{
        ComponentView, DependencyView, LicenseView, SbomMetadataView, SbomReadModel, SeverityView,
        VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
    };
    use crate::i18n::Locale;
    use crate::ports::outbound::SbomFormatter;
    use std::collections::HashMap;

    fn create_test_read_model() -> SbomReadModel {
        SbomReadModel {
            metadata: SbomMetadataView {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                tool_name: "uv-sbom".to_string(),
                tool_version: "1.0.0".to_string(),
                serial_number: "urn:uuid:test-123".to_string(),
                component: None,
            },
            components: vec![
                ComponentView {
                    bom_ref: "pkg:pypi/requests@2.31.0".to_string(),
                    name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                    purl: "pkg:pypi/requests@2.31.0".to_string(),
                    license: Some(LicenseView {
                        spdx_id: Some("Apache-2.0".to_string()),
                        name: "Apache License 2.0".to_string(),
                        url: None,
                    }),
                    description: Some("HTTP library".to_string()),
                    sha256_hash: None,
                    is_direct_dependency: true,
                },
                ComponentView {
                    bom_ref: "pkg:pypi/urllib3@1.26.0".to_string(),
                    name: "urllib3".to_string(),
                    version: "1.26.0".to_string(),
                    purl: "pkg:pypi/urllib3@1.26.0".to_string(),
                    license: Some(LicenseView {
                        spdx_id: Some("MIT".to_string()),
                        name: "MIT License".to_string(),
                        url: None,
                    }),
                    description: None,
                    sha256_hash: None,
                    is_direct_dependency: false,
                },
            ],
            dependencies: None,
            vulnerabilities: None,
            license_compliance: None,
            resolution_guide: None,
            upgrade_recommendations: None,
        }
    }

    // ============================================================
    // PyPI hyperlink tests
    // ============================================================

    #[test]
    fn test_normalize_for_pypi_underscore() {
        assert_eq!(normalize_for_pypi("typing_extensions"), "typing-extensions");
    }

    #[test]
    fn test_normalize_for_pypi_uppercase() {
        assert_eq!(normalize_for_pypi("Flask"), "flask");
    }

    #[test]
    fn test_normalize_for_pypi_already_normalized() {
        assert_eq!(normalize_for_pypi("ruamel-yaml"), "ruamel-yaml");
    }

    #[test]
    fn test_package_to_pypi_link_simple() {
        assert_eq!(
            package_to_pypi_link("requests"),
            "[requests](https://pypi.org/project/requests/)"
        );
    }

    #[test]
    fn test_package_to_pypi_link_with_underscore() {
        assert_eq!(
            package_to_pypi_link("typing_extensions"),
            "[typing_extensions](https://pypi.org/project/typing-extensions/)"
        );
    }

    #[test]
    fn test_package_to_pypi_link_with_uppercase() {
        assert_eq!(
            package_to_pypi_link("Flask"),
            "[Flask](https://pypi.org/project/flask/)"
        );
    }

    #[test]
    fn test_format_basic_contains_pypi_links() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::En);

        let markdown = formatter.format(&model).unwrap();
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
    }

    #[test]
    fn test_format_with_dependencies_contains_pypi_links() {
        let mut model = create_test_read_model();
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );

        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Direct dependencies section should have PyPI link
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        // Transitive dependencies section should have PyPI link
        assert!(markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
    }

    #[test]
    fn test_vulnerability_table_contains_pypi_links() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(9.8),
                cvss_vector: None,
                severity: SeverityView::Critical,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: true,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
    }

    // ============================================================
    // Verified packages (--verify-links) tests
    // ============================================================

    #[test]
    fn test_format_with_verified_packages_only_verified_get_links() {
        let model = create_test_read_model();
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        // "urllib3" is NOT in verified set

        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // "requests" is verified → gets a hyperlink
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        // "urllib3" is NOT verified → plain text, no hyperlink
        assert!(!markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
        assert!(markdown.contains("| urllib3 |"));
    }

    #[test]
    fn test_format_without_verified_packages_all_get_links() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Without verification, all packages get hyperlinks
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
    }

    #[test]
    fn test_format_with_empty_verified_set_no_links() {
        let model = create_test_read_model();
        let verified = HashSet::new();

        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Empty verified set → no packages get hyperlinks
        assert!(!markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(!markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
        assert!(markdown.contains("| requests |"));
        assert!(markdown.contains("| urllib3 |"));
    }

    #[test]
    fn test_format_vulnerability_with_verified_packages() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1234".to_string(),
                affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                affected_component_name: "requests".to_string(),
                affected_version: "2.31.0".to_string(),
                cvss_score: Some(9.8),
                cvss_vector: None,
                severity: SeverityView::Critical,
                fixed_version: Some("2.32.0".to_string()),
                description: None,
                source_url: None,
            }],
            informational: vec![],
            threshold_exceeded: true,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 1,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        // "requests" is NOT in verified set
        let verified = HashSet::new();
        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Vulnerability table should show plain text for unverified package
        assert!(!markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("| requests |"));
    }

    #[test]
    fn test_format_package_name_with_none_verified() {
        let result = format_package_name("requests", None);
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    #[test]
    fn test_format_package_name_with_verified_present() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let result = format_package_name("requests", Some(&verified));
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    #[test]
    fn test_format_package_name_with_verified_absent() {
        let verified = HashSet::new();
        let result = format_package_name("nonexistent-pkg", Some(&verified));
        assert_eq!(result, "nonexistent-pkg");
    }

    // ============================================================
    // Vulnerability ID hyperlink tests
    // ============================================================

    #[test]
    fn test_vulnerability_id_to_link_cve() {
        assert_eq!(
            vulnerability_id_to_link("CVE-2024-1234"),
            "[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_ghsa() {
        assert_eq!(
            vulnerability_id_to_link("GHSA-abcd-efgh-ijkl"),
            "[GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_pysec() {
        assert_eq!(
            vulnerability_id_to_link("PYSEC-2021-108"),
            "[PYSEC-2021-108](https://osv.dev/vulnerability/PYSEC-2021-108)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_rustsec() {
        assert_eq!(
            vulnerability_id_to_link("RUSTSEC-2023-0001"),
            "[RUSTSEC-2023-0001](https://osv.dev/vulnerability/RUSTSEC-2023-0001)"
        );
    }
}
