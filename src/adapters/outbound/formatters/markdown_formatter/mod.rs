mod helpers;
mod links;
mod section;
mod table;
mod vuln_render;

use crate::application::read_models::SbomReadModel;
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::SbomFormatter;
use crate::shared::Result;
use std::collections::HashSet;

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

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new(Locale::En)
    }
}

impl SbomFormatter for MarkdownFormatter {
    fn format(&self, model: &SbomReadModel) -> Result<String> {
        let mut output = String::new();

        section::render_summary(
            self.messages,
            &mut output,
            &model.components,
            model.vulnerabilities.as_ref(),
            model.license_compliance.as_ref(),
        );
        section::render_header(self.messages, &mut output);
        section::render_components(
            self.messages,
            self.verified_packages.as_ref(),
            &mut output,
            &model.components,
        );
        if let Some(deps) = &model.dependencies {
            section::render_dependencies(
                self.messages,
                self.verified_packages.as_ref(),
                &mut output,
                deps,
                &model.components,
            );
        }
        if let Some(vulns) = &model.vulnerabilities {
            vuln_render::render_vulnerabilities(
                self.messages,
                self.verified_packages.as_ref(),
                &mut output,
                vulns,
            );
        }
        if let Some(guide) = &model.resolution_guide {
            if !guide.entries.is_empty() {
                section::render_resolution_guide(
                    self.messages,
                    &mut output,
                    guide,
                    model.upgrade_recommendations.as_ref(),
                );
            }
        }
        if let Some(compliance) = &model.license_compliance {
            section::render_license_compliance(self.messages, &mut output, compliance);
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        ComponentView, DependencyView, LicenseView, SbomMetadataView, SbomReadModel, SeverityView,
        VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
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
        assert!(markdown.contains("Apache-2.0"));
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
        let summary_pos = markdown.find("## Summary");
        let sbom_pos = markdown.find("# Software Bill of Materials (SBOM)");
        let inventory_pos = markdown.find("## Component Inventory");
        let direct_pos = markdown.find("## Direct Dependencies");
        let transitive_pos = markdown.find("## Transitive Dependencies");

        assert!(summary_pos.is_some());
        assert!(sbom_pos.is_some());
        assert!(inventory_pos.is_some());
        assert!(direct_pos.is_some());
        assert!(transitive_pos.is_some());

        // Verify ordering: summary must come before all other sections
        assert!(summary_pos.unwrap() < sbom_pos.unwrap());
        assert!(sbom_pos.unwrap() < inventory_pos.unwrap());
        assert!(inventory_pos.unwrap() < direct_pos.unwrap());
        assert!(direct_pos.unwrap() < transitive_pos.unwrap());
    }

    #[test]
    fn test_summary_appears_before_all_sections() {
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

        let summary_pos = markdown.find("## Summary").unwrap();
        let header_pos = markdown
            .find("# Software Bill of Materials (SBOM)")
            .unwrap();
        let inventory_pos = markdown.find("## Component Inventory").unwrap();
        let direct_pos = markdown.find("## Direct Dependencies").unwrap();
        let transitive_pos = markdown.find("## Transitive Dependencies").unwrap();

        assert!(summary_pos < header_pos);
        assert!(summary_pos < inventory_pos);
        assert!(summary_pos < direct_pos);
        assert!(summary_pos < transitive_pos);
    }

    #[test]
    fn test_summary_vuln_skipped_note_when_no_network() {
        let model = create_test_read_model(); // vulnerabilities: None

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("_Vulnerability check skipped._"));
    }

    #[test]
    fn test_summary_overall_action_required_when_critical_vuln() {
        let mut model = create_test_read_model();
        model.vulnerabilities = Some(VulnerabilityReportView {
            actionable: vec![VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-9999".to_string(),
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

        assert!(markdown.contains("**Overall: Action required**"));
    }

    #[test]
    fn test_summary_overall_no_issues_when_clean() {
        let model = create_test_read_model(); // no vulns, no license violations

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("**Overall: No issues found** ✅"));
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
    fn test_lang_ja_license_violations_count_is_japanese() {
        use crate::application::read_models::{
            LicenseComplianceSummary, LicenseComplianceView, LicenseViolationView,
        };

        let mut model = create_test_read_model();
        model.license_compliance = Some(LicenseComplianceView {
            has_violations: true,
            violations: vec![
                LicenseViolationView {
                    package_name: "chardet".to_string(),
                    package_version: "3.0.4".to_string(),
                    license: "LGPL-2.1-only".to_string(),
                    reason: "Denied by policy".to_string(),
                    matched_pattern: Some("LGPL-*".to_string()),
                },
                LicenseViolationView {
                    package_name: "foo".to_string(),
                    package_version: "1.0.0".to_string(),
                    license: "GPL-3.0-only".to_string(),
                    reason: "Denied by policy".to_string(),
                    matched_pattern: Some("GPL-*".to_string()),
                },
                LicenseViolationView {
                    package_name: "bar".to_string(),
                    package_version: "2.0.0".to_string(),
                    license: "AGPL-3.0-only".to_string(),
                    reason: "Denied by policy".to_string(),
                    matched_pattern: Some("AGPL-*".to_string()),
                },
                LicenseViolationView {
                    package_name: "baz".to_string(),
                    package_version: "0.1.0".to_string(),
                    license: "GPL-2.0-only".to_string(),
                    reason: "Denied by policy".to_string(),
                    matched_pattern: Some("GPL-*".to_string()),
                },
            ],
            warnings: vec![],
            summary: LicenseComplianceSummary {
                violation_count: 4,
                warning_count: 0,
            },
        });

        let formatter = MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        // Japanese summary must appear
        assert!(
            markdown.contains("**4 件のライセンス違反が見つかりました。**"),
            "Expected Japanese violation count summary, got:\n{markdown}"
        );
        // English hardcoded string must NOT appear
        assert!(
            !markdown.contains("license violations found"),
            "English violation summary leaked into JA output:\n{markdown}"
        );
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

    #[test]
    fn test_format_license_falls_back_to_name_when_spdx_id_is_none() {
        let mut model = create_test_read_model();
        model.components.push(ComponentView {
            bom_ref: "pkg:pypi/somelib@1.0.0".to_string(),
            name: "somelib".to_string(),
            version: "1.0.0".to_string(),
            purl: "pkg:pypi/somelib@1.0.0".to_string(),
            license: Some(LicenseView {
                spdx_id: None,
                name: "Some Custom License".to_string(),
                url: None,
            }),
            description: None,
            sha256_hash: None,
            is_direct_dependency: false,
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Some Custom License"));
    }
}
