use crate::application::read_models::{
    ComponentView, DependencyView, LicenseComplianceView, ResolutionGuideView,
    UpgradeRecommendationView,
};
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

/// Renders the license compliance section
pub(super) fn render_license_compliance(
    messages: &'static Messages,
    output: &mut String,
    compliance: &LicenseComplianceView,
) {
    output.push('\n');
    output.push_str(messages.section_license_compliance);
    output.push_str("\n\n");

    // Summary
    if compliance.has_violations {
        output.push_str(&format!(
            "**{} license {} found.**\n\n",
            compliance.summary.violation_count,
            if compliance.summary.violation_count == 1 {
                "violation"
            } else {
                "violations"
            }
        ));
    } else {
        output.push_str(messages.label_no_license_violations);
        output.push_str("\n\n");
    }

    // Violations table
    if !compliance.violations.is_empty() {
        output.push_str(messages.section_violations);
        output.push_str("\n\n");
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            messages.col_package,
            messages.col_version,
            messages.col_license,
            messages.col_reason,
            messages.col_matched_pattern,
        ));
        output.push_str(&super::table::make_separator(&[
            messages.col_package,
            messages.col_version,
            messages.col_license,
            messages.col_reason,
            messages.col_matched_pattern,
        ]));

        for v in &compliance.violations {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                super::table::escape_markdown_table_cell(&v.package_name),
                super::table::escape_markdown_table_cell(&v.package_version),
                super::table::escape_markdown_table_cell(&v.license),
                super::table::escape_markdown_table_cell(&v.reason),
                v.matched_pattern.as_deref().unwrap_or("-"),
            ));
        }
        output.push('\n');
    }

    // Warnings table
    if !compliance.warnings.is_empty() {
        let warning_count = compliance.summary.warning_count;
        let pkg_word = if warning_count == 1 {
            messages.label_package_singular
        } else {
            messages.label_package_plural
        };
        output.push_str(messages.section_warnings);
        output.push_str("\n\n");
        output.push_str(&Messages::format(
            messages.warn_unknown_license_packages,
            &[&warning_count.to_string(), pkg_word],
        ));
        output.push_str("\n\n");
        output.push_str(&format!(
            "| {} | {} |\n",
            messages.col_package, messages.col_version,
        ));
        output.push_str(&super::table::make_separator(&[
            messages.col_package,
            messages.col_version,
        ]));

        for w in &compliance.warnings {
            output.push_str(&format!(
                "| {} | {} |\n",
                super::table::escape_markdown_table_cell(&w.package_name),
                super::table::escape_markdown_table_cell(&w.package_version),
            ));
        }
        output.push('\n');
    }
}

/// Renders the resolution guide section
pub(super) fn render_resolution_guide(
    messages: &'static Messages,
    output: &mut String,
    guide: &ResolutionGuideView,
    upgrade_recommendations: Option<&UpgradeRecommendationView>,
) {
    output.push('\n');
    output.push_str(messages.section_resolution_guide);
    output.push_str("\n\n");
    output.push_str(messages.desc_transitive_vuln_table);
    output.push_str("\n\n");

    if upgrade_recommendations.is_some() {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            messages.col_vulnerable_package,
            messages.col_current,
            messages.col_fixed_version,
            messages.col_severity,
            messages.col_introduced_by,
            messages.col_recommended_action,
            messages.col_vuln_id,
        ));
        output.push_str(&super::table::make_separator(&[
            messages.col_vulnerable_package,
            messages.col_current,
            messages.col_fixed_version,
            messages.col_severity,
            messages.col_introduced_by,
            messages.col_recommended_action,
            messages.col_vuln_id,
        ]));
    } else {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            messages.col_vulnerable_package,
            messages.col_current,
            messages.col_fixed_version,
            messages.col_severity,
            messages.col_introduced_by,
            messages.col_vuln_id,
        ));
        output.push_str(&super::table::make_separator(&[
            messages.col_vulnerable_package,
            messages.col_current,
            messages.col_fixed_version,
            messages.col_severity,
            messages.col_introduced_by,
            messages.col_vuln_id,
        ]));
    }

    for entry in &guide.entries {
        let fixed = entry.fixed_version.as_deref().unwrap_or("N/A");
        let severity_emoji = match entry.severity {
            crate::application::read_models::SeverityView::Critical => "🔴",
            crate::application::read_models::SeverityView::High => "🟠",
            crate::application::read_models::SeverityView::Medium => "🟡",
            crate::application::read_models::SeverityView::Low => "🟢",
            crate::application::read_models::SeverityView::None => "⚪",
        };

        let introduced_by = entry
            .introduced_by
            .iter()
            .map(|ib| format!("{} ({})", ib.package_name, ib.version))
            .collect::<Vec<_>>()
            .join(", ");

        if let Some(recommendations) = upgrade_recommendations {
            let action = super::helpers::find_upgrade_action(
                messages,
                recommendations,
                &entry.vulnerability_id,
                &entry.introduced_by,
            );
            output.push_str(&format!(
                "| {} | {} | {} | {} {} | {} | {} | {} |\n",
                super::table::escape_markdown_table_cell(&entry.vulnerable_package),
                super::table::escape_markdown_table_cell(&entry.current_version),
                super::table::escape_markdown_table_cell(fixed),
                severity_emoji,
                entry.severity.as_str(),
                super::table::escape_markdown_table_cell(&introduced_by),
                super::table::escape_markdown_table_cell(&action),
                super::links::vulnerability_id_to_link(&entry.vulnerability_id),
            ));
        } else {
            output.push_str(&format!(
                "| {} | {} | {} | {} {} | {} | {} |\n",
                super::table::escape_markdown_table_cell(&entry.vulnerable_package),
                super::table::escape_markdown_table_cell(&entry.current_version),
                super::table::escape_markdown_table_cell(fixed),
                severity_emoji,
                entry.severity.as_str(),
                super::table::escape_markdown_table_cell(&introduced_by),
                super::links::vulnerability_id_to_link(&entry.vulnerability_id),
            ));
        }
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use crate::application::read_models::{
        ComponentView, IntroducedByView, LicenseView, ResolutionEntryView, ResolutionGuideView,
        SbomMetadataView, SbomReadModel, SeverityView, UpgradeEntryView, UpgradeRecommendationView,
    };
    use crate::i18n::Locale;
    use crate::ports::outbound::SbomFormatter;

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

    #[test]
    fn test_render_resolution_guide_with_entries() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "urllib3".to_string(),
                current_version: "1.26.15".to_string(),
                fixed_version: Some(">= 2.0.7".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("## Vulnerability Resolution Guide"));
        assert!(markdown.contains("urllib3"));
        assert!(markdown.contains("1.26.15"));
        assert!(markdown.contains(">= 2.0.7"));
        assert!(markdown.contains("🟠 HIGH"));
        assert!(markdown.contains("requests (2.31.0)"));
        assert!(
            markdown.contains("[CVE-2024-XXXXX](https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX)")
        );
    }

    #[test]
    fn test_render_resolution_guide_multiple_introduced_by() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "certifi".to_string(),
                current_version: "2023.7.22".to_string(),
                fixed_version: Some(">= 2024.2.2".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-YYYYY".to_string(),
                introduced_by: vec![
                    IntroducedByView {
                        package_name: "requests".to_string(),
                        version: "2.31.0".to_string(),
                    },
                    IntroducedByView {
                        package_name: "httpx".to_string(),
                        version: "0.25.0".to_string(),
                    },
                ],
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("requests (2.31.0), httpx (0.25.0)"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_empty() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView { entries: vec![] });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("## Vulnerability Resolution Guide"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_none() {
        let model = create_test_read_model();
        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("## Vulnerability Resolution Guide"));
    }

    #[test]
    fn test_resolution_guide_ghsa_link() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "urllib3".to_string(),
                current_version: "1.26.15".to_string(),
                fixed_version: None,
                severity: SeverityView::Medium,
                vulnerability_id: "GHSA-abcd-efgh-ijkl".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown
            .contains("[GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)"));
        assert!(markdown.contains("N/A")); // fixed_version is None
    }

    #[test]
    fn test_render_resolution_guide_with_upgradable_recommendation() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "urllib3".to_string(),
                current_version: "1.26.15".to_string(),
                fixed_version: Some(">= 2.0.7".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Upgradable {
                direct_dep: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                target_version: "2.32.3".to_string(),
                transitive_dep: "urllib3".to_string(),
                resolved_version: "2.2.1".to_string(),
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)"));
    }

    #[test]
    fn test_render_resolution_guide_with_unresolvable_recommendation() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "idna".to_string(),
                current_version: "3.6".to_string(),
                fixed_version: Some(">= 3.7".to_string()),
                severity: SeverityView::Medium,
                vulnerability_id: "GHSA-ZZZZZ".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "httpx".to_string(),
                    version: "0.25.0".to_string(),
                }],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Unresolvable {
                direct_dep: "httpx".to_string(),
                reason: "latest httpx still pins idna < 3.7".to_string(),
                vulnerability_id: "GHSA-ZZZZZ".to_string(),
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("⚠️ Cannot resolve: latest httpx still pins idna < 3.7"));
    }

    #[test]
    fn test_render_resolution_guide_with_simulation_failed() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "urllib3".to_string(),
                current_version: "1.26.15".to_string(),
                fixed_version: None,
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::SimulationFailed {
                direct_dep: "requests".to_string(),
                error: "dependency resolution timed out".to_string(),
            }],
        });

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("❓ Could not analyze: dependency resolution timed out"));
    }

    #[test]
    fn test_render_resolution_guide_no_recommendations_omits_column() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "urllib3".to_string(),
                current_version: "1.26.15".to_string(),
                fixed_version: Some(">= 2.0.7".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
            }],
        });
        // upgrade_recommendations is None (default in test model)

        let formatter = super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("Recommended Action"));
        assert!(markdown.contains("## Vulnerability Resolution Guide"));
    }
}
