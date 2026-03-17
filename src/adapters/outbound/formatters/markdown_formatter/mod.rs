mod helpers;
mod links;
mod section;
mod table;
mod vuln_render;

use crate::application::read_models::{
    ComponentView, DependencyView, LicenseComplianceView, ResolutionGuideView, SbomReadModel,
    UpgradeRecommendationView, VulnerabilityReportView,
};
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::SbomFormatter;
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

/// MarkdownFormatter adapter for generating detailed Markdown SBOM with dependency information
///
/// This adapter implements the SbomFormatter port for Markdown format,
/// including dependency graph visualization.
pub struct MarkdownFormatter {
    /// When Some, only packages in this set get PyPI hyperlinks.
    /// When None, all packages get PyPI hyperlinks (default behavior).
    verified_packages: Option<HashSet<String>>,
    messages: &'static Messages,
}

impl MarkdownFormatter {
    pub fn new(locale: Locale) -> Self {
        Self {
            verified_packages: None,
            messages: Messages::for_locale(locale),
        }
    }

    /// Creates a new MarkdownFormatter with a set of verified PyPI packages.
    /// Only packages in the set will get hyperlinks; others render as plain text.
    pub fn with_verified_packages(verified_packages: HashSet<String>, locale: Locale) -> Self {
        Self {
            verified_packages: Some(verified_packages),
            messages: Messages::for_locale(locale),
        }
    }
}

/// Helper methods for rendering sections
impl MarkdownFormatter {
    /// Renders the header section
    fn render_header(&self, output: &mut String) {
        output.push_str(self.messages.section_sbom_title);
        output.push_str("\n\n");
    }

    /// Renders the components section
    fn render_components(&self, output: &mut String, components: &[ComponentView]) {
        output.push_str(self.messages.section_component_inventory);
        output.push_str("\n\n");
        output.push_str(self.messages.desc_sbom_report);
        output.push_str("\n\n");
        output.push_str(&table::table_header(self.messages));
        output.push_str(&table::table_separator(self.messages));

        for component in components {
            let license = component
                .license
                .as_ref()
                .map(|l| l.name.as_str())
                .unwrap_or("N/A");
            let description = component.description.as_deref().unwrap_or("");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                links::format_package_name(&component.name, self.verified_packages.as_ref()),
                table::escape_markdown_table_cell(&component.version),
                table::escape_markdown_table_cell(license),
                table::escape_markdown_table_cell(description)
            ));
        }
        output.push('\n');
    }

    /// Renders the dependencies section
    fn render_dependencies(
        &self,
        output: &mut String,
        deps: &DependencyView,
        components: &[ComponentView],
    ) {
        // Create component lookup map by bom_ref
        let component_map: HashMap<&str, &ComponentView> =
            components.iter().map(|c| (c.bom_ref.as_str(), c)).collect();

        // Direct Dependencies section
        output.push_str(self.messages.section_direct_deps);
        output.push_str("\n\n");
        output.push_str(self.messages.desc_direct_deps);
        output.push_str("\n\n");

        if !deps.direct.is_empty() {
            output.push_str(&table::table_header(self.messages));
            output.push_str(&table::table_separator(self.messages));

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
                        links::format_package_name(
                            &component.name,
                            self.verified_packages.as_ref()
                        ),
                        table::escape_markdown_table_cell(&component.version),
                        table::escape_markdown_table_cell(license),
                        table::escape_markdown_table_cell(description)
                    ));
                }
            }
            output.push('\n');
        } else {
            output.push_str(self.messages.label_no_direct_deps);
            output.push_str("\n\n");
        }

        // Transitive Dependencies section
        output.push_str(self.messages.section_transitive_deps);
        output.push_str("\n\n");
        output.push_str(self.messages.desc_transitive_deps);
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

                    output.push_str(&Messages::format(
                        self.messages.deps_for_header,
                        &[parent_name],
                    ));
                    output.push_str("\n\n");
                    output.push_str(&table::table_header(self.messages));
                    output.push_str(&table::table_separator(self.messages));

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
                                links::format_package_name(
                                    &component.name,
                                    self.verified_packages.as_ref()
                                ),
                                table::escape_markdown_table_cell(&component.version),
                                table::escape_markdown_table_cell(license),
                                table::escape_markdown_table_cell(description)
                            ));
                        }
                    }
                    output.push('\n');
                }
            }
        } else {
            output.push_str(self.messages.label_no_transitive_deps);
            output.push_str("\n\n");
        }
    }

    /// Renders the vulnerabilities section
    fn render_vulnerabilities(&self, output: &mut String, vulns: &VulnerabilityReportView) {
        vuln_render::render_vulnerabilities(
            self.messages,
            self.verified_packages.as_ref(),
            output,
            vulns,
        );
    }

    /// Renders the license compliance section
    fn render_license_compliance(&self, output: &mut String, compliance: &LicenseComplianceView) {
        output.push('\n');
        output.push_str(self.messages.section_license_compliance);
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
            output.push_str(self.messages.label_no_license_violations);
            output.push_str("\n\n");
        }

        // Violations table
        if !compliance.violations.is_empty() {
            output.push_str(self.messages.section_violations);
            output.push_str("\n\n");
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                self.messages.col_package,
                self.messages.col_version,
                self.messages.col_license,
                self.messages.col_reason,
                self.messages.col_matched_pattern,
            ));
            output.push_str(&table::make_separator(&[
                self.messages.col_package,
                self.messages.col_version,
                self.messages.col_license,
                self.messages.col_reason,
                self.messages.col_matched_pattern,
            ]));

            for v in &compliance.violations {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    table::escape_markdown_table_cell(&v.package_name),
                    table::escape_markdown_table_cell(&v.package_version),
                    table::escape_markdown_table_cell(&v.license),
                    table::escape_markdown_table_cell(&v.reason),
                    v.matched_pattern.as_deref().unwrap_or("-"),
                ));
            }
            output.push('\n');
        }

        // Warnings table
        if !compliance.warnings.is_empty() {
            let warning_count = compliance.summary.warning_count;
            let pkg_word = if warning_count == 1 {
                self.messages.label_package_singular
            } else {
                self.messages.label_package_plural
            };
            output.push_str(self.messages.section_warnings);
            output.push_str("\n\n");
            output.push_str(&Messages::format(
                self.messages.warn_unknown_license_packages,
                &[&warning_count.to_string(), pkg_word],
            ));
            output.push_str("\n\n");
            output.push_str(&format!(
                "| {} | {} |\n",
                self.messages.col_package, self.messages.col_version,
            ));
            output.push_str(&table::make_separator(&[
                self.messages.col_package,
                self.messages.col_version,
            ]));

            for w in &compliance.warnings {
                output.push_str(&format!(
                    "| {} | {} |\n",
                    table::escape_markdown_table_cell(&w.package_name),
                    table::escape_markdown_table_cell(&w.package_version),
                ));
            }
            output.push('\n');
        }
    }

    /// Renders the resolution guide section
    fn render_resolution_guide(
        &self,
        output: &mut String,
        guide: &ResolutionGuideView,
        upgrade_recommendations: Option<&UpgradeRecommendationView>,
    ) {
        output.push('\n');
        output.push_str(self.messages.section_resolution_guide);
        output.push_str("\n\n");
        output.push_str(self.messages.desc_transitive_vuln_table);
        output.push_str("\n\n");

        if upgrade_recommendations.is_some() {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                self.messages.col_vulnerable_package,
                self.messages.col_current,
                self.messages.col_fixed_version,
                self.messages.col_severity,
                self.messages.col_introduced_by,
                self.messages.col_recommended_action,
                self.messages.col_vuln_id,
            ));
            output.push_str(&table::make_separator(&[
                self.messages.col_vulnerable_package,
                self.messages.col_current,
                self.messages.col_fixed_version,
                self.messages.col_severity,
                self.messages.col_introduced_by,
                self.messages.col_recommended_action,
                self.messages.col_vuln_id,
            ]));
        } else {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                self.messages.col_vulnerable_package,
                self.messages.col_current,
                self.messages.col_fixed_version,
                self.messages.col_severity,
                self.messages.col_introduced_by,
                self.messages.col_vuln_id,
            ));
            output.push_str(&table::make_separator(&[
                self.messages.col_vulnerable_package,
                self.messages.col_current,
                self.messages.col_fixed_version,
                self.messages.col_severity,
                self.messages.col_introduced_by,
                self.messages.col_vuln_id,
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
                let action = helpers::find_upgrade_action(
                    self.messages,
                    recommendations,
                    &entry.vulnerability_id,
                    &entry.introduced_by,
                );
                output.push_str(&format!(
                    "| {} | {} | {} | {} {} | {} | {} | {} |\n",
                    table::escape_markdown_table_cell(&entry.vulnerable_package),
                    table::escape_markdown_table_cell(&entry.current_version),
                    table::escape_markdown_table_cell(fixed),
                    severity_emoji,
                    entry.severity.as_str(),
                    table::escape_markdown_table_cell(&introduced_by),
                    table::escape_markdown_table_cell(&action),
                    links::vulnerability_id_to_link(&entry.vulnerability_id),
                ));
            } else {
                output.push_str(&format!(
                    "| {} | {} | {} | {} {} | {} | {} |\n",
                    table::escape_markdown_table_cell(&entry.vulnerable_package),
                    table::escape_markdown_table_cell(&entry.current_version),
                    table::escape_markdown_table_cell(fixed),
                    severity_emoji,
                    entry.severity.as_str(),
                    table::escape_markdown_table_cell(&introduced_by),
                    links::vulnerability_id_to_link(&entry.vulnerability_id),
                ));
            }
        }
        output.push('\n');
    }
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new(Locale::En)
    }
}

impl SbomFormatter for MarkdownFormatter {
    fn format(&self, model: &SbomReadModel) -> Result<String> {
        let mut output = String::new();

        // Header section
        self.render_header(&mut output);

        // Components section
        self.render_components(&mut output, &model.components);

        // Dependencies section (if present)
        if let Some(deps) = &model.dependencies {
            self.render_dependencies(&mut output, deps, &model.components);
        }

        // Vulnerabilities section (if present)
        if let Some(vulns) = &model.vulnerabilities {
            self.render_vulnerabilities(&mut output, vulns);
        }

        // Resolution guide section (if present)
        if let Some(guide) = &model.resolution_guide {
            if !guide.entries.is_empty() {
                self.render_resolution_guide(
                    &mut output,
                    guide,
                    model.upgrade_recommendations.as_ref(),
                );
            }
        }

        // License compliance section (if present)
        if let Some(compliance) = &model.license_compliance {
            self.render_license_compliance(&mut output, compliance);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        LicenseView, SbomMetadataView, SeverityView, VulnerabilitySummary, VulnerabilityView,
    };
    use crate::i18n::Locale;
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

    #[test]
    fn test_format_basic() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::En);

        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("# Software Bill of Materials (SBOM)"));
        assert!(markdown.contains("## Component Inventory"));
        assert!(markdown.contains("requests"));
        assert!(markdown.contains("2.31.0"));
        assert!(markdown.contains("Apache License 2.0"));
        assert!(markdown.contains("urllib3"));
    }

    #[test]
    fn test_format_with_dependencies() {
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
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Direct Dependencies"));
        assert!(markdown.contains("## Transitive Dependencies"));
        assert!(markdown.contains("### Dependencies for requests"));
        assert!(markdown.contains("urllib3"));
    }

    #[test]
    fn test_format_with_vulnerabilities() {
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
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Vulnerability Report"));
        assert!(markdown.contains("### ⚠️Warning Found 1 vulnerability in 1 package."));
        assert!(
            markdown.contains("[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)")
        );
        assert!(markdown.contains("9.8"));
        assert!(markdown.contains("🔴"));
        assert!(markdown.contains("CRITICAL"));
        assert!(markdown.contains("2.32.0"));
    }

    #[test]
    fn test_format_with_informational_vulnerabilities() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![],
            informational: vec![VulnerabilityView {
                bom_ref: "vuln-002".to_string(),
                id: "CVE-2024-5678".to_string(),
                affected_component: "pkg:pypi/urllib3@1.26.0".to_string(),
                affected_component_name: "urllib3".to_string(),
                affected_version: "1.26.0".to_string(),
                cvss_score: Some(3.1),
                cvss_vector: None,
                severity: SeverityView::Low,
                fixed_version: None,
                description: None,
                source_url: None,
            }],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 1,
                actionable_count: 0,
                informational_count: 1,
                affected_package_count: 1,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("### ⚠️Warning No vulnerabilities found above threshold."));
        assert!(markdown.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(
            markdown.contains("[CVE-2024-5678](https://nvd.nist.gov/vuln/detail/CVE-2024-5678)")
        );
        assert!(markdown.contains("🟢"));
        assert!(markdown.contains("LOW"));
    }

    #[test]
    fn test_format_output_section_ordering() {
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
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();

        // Check key sections exist in correct order
        let sbom_pos = markdown.find("# Software Bill of Materials (SBOM)");
        let inventory_pos = markdown.find("## Component Inventory");
        let direct_pos = markdown.find("## Direct Dependencies");
        let transitive_pos = markdown.find("## Transitive Dependencies");

        assert!(sbom_pos.is_some());
        assert!(inventory_pos.is_some());
        assert!(direct_pos.is_some());
        assert!(transitive_pos.is_some());

        // Verify ordering
        assert!(sbom_pos.unwrap() < inventory_pos.unwrap());
        assert!(inventory_pos.unwrap() < direct_pos.unwrap());
        assert!(direct_pos.unwrap() < transitive_pos.unwrap());
    }

    #[test]
    fn test_format_vulnerability_section_ordering() {
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
            informational: vec![VulnerabilityView {
                bom_ref: "vuln-002".to_string(),
                id: "CVE-2024-5678".to_string(),
                affected_component: "pkg:pypi/urllib3@1.26.0".to_string(),
                affected_component_name: "urllib3".to_string(),
                affected_version: "1.26.0".to_string(),
                cvss_score: Some(2.0),
                cvss_vector: None,
                severity: SeverityView::Low,
                fixed_version: None,
                description: None,
                source_url: None,
            }],
            threshold_exceeded: true,
            summary: VulnerabilitySummary {
                total_count: 2,
                actionable_count: 1,
                informational_count: 1,
                affected_package_count: 2,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Verify sections appear in correct order
        let summary_pos = markdown.find("**Found 2 vulnerabilities in 2 packages.**");
        let warning_pos = markdown.find("### ⚠️Warning");
        let info_pos = markdown.find("### ℹ️Info");
        let attribution_pos = markdown.find("*Vulnerability data provided by");

        assert!(summary_pos.is_some());
        assert!(warning_pos.is_some());
        assert!(info_pos.is_some());
        assert!(attribution_pos.is_some());

        assert!(summary_pos.unwrap() < warning_pos.unwrap());
        assert!(warning_pos.unwrap() < info_pos.unwrap());
        assert!(info_pos.unwrap() < attribution_pos.unwrap());
    }

    // ============================================================
    // Resolution guide tests
    // ============================================================

    #[test]
    fn test_render_resolution_guide_with_entries() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
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
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("requests (2.31.0), httpx (0.25.0)"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_empty() {
        use crate::application::read_models::ResolutionGuideView;

        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView { entries: vec![] });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("## Vulnerability Resolution Guide"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_none() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("## Vulnerability Resolution Guide"));
    }

    #[test]
    fn test_resolution_guide_ghsa_link() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown
            .contains("[GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)"));
        assert!(markdown.contains("N/A")); // fixed_version is None
    }

    // ============================================================
    // Upgrade recommendation rendering tests
    // ============================================================

    #[test]
    fn test_render_resolution_guide_with_upgradable_recommendation() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView, UpgradeEntryView,
            UpgradeRecommendationView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("⬆️ Upgrade requests → 2.32.3 (resolves urllib3 to 2.2.1)"));
    }

    #[test]
    fn test_render_resolution_guide_with_unresolvable_recommendation() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView, UpgradeEntryView,
            UpgradeRecommendationView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("⚠️ Cannot resolve: latest httpx still pins idna < 3.7"));
    }

    #[test]
    fn test_render_resolution_guide_with_simulation_failed() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView, UpgradeEntryView,
            UpgradeRecommendationView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("❓ Could not analyze: dependency resolution timed out"));
    }

    #[test]
    fn test_render_resolution_guide_no_recommendations_omits_column() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("Recommended Action"));
        assert!(markdown.contains("## Vulnerability Resolution Guide"));
    }

    // ===== Tests for --lang option (i18n) =====

    #[test]
    fn test_lang_ja_markdown_output_contains_japanese_headers() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::Ja);

        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("# ソフトウェア部品表 (SBOM)"));
        assert!(markdown.contains("## コンポーネント一覧"));
        assert!(!markdown.contains("# Software Bill of Materials (SBOM)"));
        assert!(!markdown.contains("## Component Inventory"));
    }

    #[test]
    fn test_lang_ja_markdown_output_contains_japanese_table_column() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::Ja);

        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("パッケージ"));
        assert!(markdown.contains("バージョン"));
        assert!(markdown.contains("ライセンス"));
    }

    #[test]
    fn test_lang_en_markdown_output_unchanged() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::En);

        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("# Software Bill of Materials (SBOM)"));
        assert!(markdown.contains("## Component Inventory"));
        assert!(markdown.contains("Package"));
        assert!(markdown.contains("Version"));
        assert!(markdown.contains("License"));
        assert!(!markdown.contains("パッケージ"));
        assert!(!markdown.contains("ソフトウェア部品表"));
    }

    #[test]
    fn test_lang_ja_with_dependencies_contains_japanese_dep_headers() {
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

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("## 直接依存パッケージ"));
        assert!(markdown.contains("## 間接依存パッケージ"));
        assert!(!markdown.contains("## Direct Dependencies"));
        assert!(!markdown.contains("## Transitive Dependencies"));
        assert!(markdown.contains("### requestsの依存パッケージ"));
        assert!(!markdown.contains("### Dependencies for requests"));
    }

    #[test]
    fn test_lang_ja_section_descriptions_are_japanese() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains(
            "このプロジェクトに含まれるすべてのソフトウェアコンポーネントとライブラリの一覧です。"
        ));
        assert!(!markdown.contains("A comprehensive list of all software components"));
    }

    #[test]
    fn test_lang_ja_no_direct_deps_label_is_japanese() {
        let mut model = create_test_read_model();
        model.dependencies = Some(DependencyView {
            direct: vec![],
            transitive: HashMap::new(),
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("*直接依存パッケージなし*"));
        assert!(!markdown.contains("*No direct dependencies*"));
    }

    #[test]
    fn test_lang_ja_no_transitive_deps_label_is_japanese() {
        let mut model = create_test_read_model();
        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive: HashMap::new(),
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("*間接依存パッケージなし*"));
        assert!(!markdown.contains("*No transitive dependencies*"));
    }

    #[test]
    fn test_lang_ja_vuln_above_threshold_warning_is_japanese() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 0,
                actionable_count: 0,
                informational_count: 0,
                affected_package_count: 0,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("### ⚠️警告 閾値を超える脆弱性は見つかりませんでした。"));
        assert!(!markdown.contains("### ⚠️Warning No vulnerabilities found above threshold."));
    }

    #[test]
    fn test_lang_ja_actionable_vuln_count_is_japanese() {
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

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("### ⚠️警告 1件の脆弱性が1個のパッケージで見つかりました。"));
        assert!(!markdown.contains("### ⚠️Warning Found"));
    }

    #[test]
    fn test_lang_ja_osv_attribution_is_japanese() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![],
            informational: vec![],
            threshold_exceeded: false,
            summary: VulnerabilitySummary {
                total_count: 0,
                actionable_count: 0,
                informational_count: 0,
                affected_package_count: 0,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("*脆弱性データは [OSV](https://osv.dev) より CC-BY 4.0 ライセンスの下で提供されています*"));
        assert!(!markdown.contains("*Vulnerability data provided by"));
    }

    #[test]
    fn test_lang_ja_no_license_violations_is_japanese() {
        use crate::application::read_models::{LicenseComplianceSummary, LicenseComplianceView};

        let mut model = create_test_read_model();
        model.license_compliance = Some(LicenseComplianceView {
            has_violations: false,
            violations: vec![],
            warnings: vec![],
            summary: LicenseComplianceSummary {
                violation_count: 0,
                warning_count: 0,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("**ライセンス違反は見つかりませんでした。**"));
        assert!(!markdown.contains("**No license violations found.**"));
    }

    #[test]
    fn test_lang_ja_resolution_guide_action_is_japanese() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView, UpgradeEntryView,
            UpgradeRecommendationView,
        };

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

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("推奨アクション"));
        assert!(markdown.contains("⬆️ requestsを2.32.3にアップグレード（urllib3が2.2.1に解決）"));
        assert!(!markdown.contains("⬆️ Upgrade"));
    }

    #[test]
    fn test_lang_ja_with_vulnerabilities_contains_japanese_vuln_headers() {
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

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("## 脆弱性レポート"));
        assert!(!markdown.contains("## Vulnerability Report"));
        // CVE ID remains in its original form regardless of locale
        assert!(markdown.contains("CVE-2024-1234"));
    }

    #[test]
    fn test_lang_ja_vuln_summary_is_japanese() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![
                VulnerabilityView {
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
                },
                VulnerabilityView {
                    bom_ref: "vuln-002".to_string(),
                    id: "CVE-2024-5678".to_string(),
                    affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                    affected_component_name: "requests".to_string(),
                    affected_version: "2.31.0".to_string(),
                    cvss_score: Some(7.5),
                    cvss_vector: None,
                    severity: SeverityView::High,
                    fixed_version: None,
                    description: None,
                    source_url: None,
                },
            ],
            informational: vec![],
            threshold_exceeded: true,
            summary: VulnerabilitySummary {
                total_count: 2,
                actionable_count: 2,
                informational_count: 0,
                affected_package_count: 1,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("**2件の脆弱性が1個のパッケージで見つかりました。**"));
        assert!(!markdown.contains("**Found"));
    }
}
