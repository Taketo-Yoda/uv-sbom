mod helpers;
mod links;
mod sections;
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

impl MarkdownFormatter {
    /// Renders the three always-present sections in fixed order: summary, header, components.
    fn render_required_sections(&self, output: &mut String, model: &SbomReadModel) {
        sections::summary::render(
            self.messages,
            output,
            &model.components,
            model.vulnerabilities.as_ref(),
            model.license_compliance.as_ref(),
            model.abandoned_packages.as_ref(),
        );
        sections::header::render(self.messages, output);
        sections::components::render(
            self.messages,
            self.verified_packages.as_ref(),
            output,
            &model.components,
        );
    }

    /// Renders the five conditional sections when present: dependencies, vulnerabilities,
    /// license compliance, abandoned packages, and resolution guide.
    fn render_optional_sections(&self, output: &mut String, model: &SbomReadModel) {
        if let Some(deps) = &model.dependencies {
            sections::dependencies::render(
                self.messages,
                self.verified_packages.as_ref(),
                output,
                deps,
                &model.components,
            );
        }
        if let Some(vulns) = &model.vulnerabilities {
            vuln_render::render_vulnerabilities(
                self.messages,
                self.verified_packages.as_ref(),
                output,
                vulns,
            );
        }
        if let Some(compliance) = &model.license_compliance {
            sections::license_compliance::render(self.messages, output, compliance);
        }
        if let Some(report) = &model.abandoned_packages {
            sections::abandoned_packages::render(self.messages, output, report);
        }
        if let Some(guide) = &model.resolution_guide {
            if !guide.entries.is_empty() {
                sections::resolution_guide::render(
                    self.messages,
                    output,
                    guide,
                    model.upgrade_recommendations.as_ref(),
                );
            }
        }
    }
}

impl SbomFormatter for MarkdownFormatter {
    fn format(&self, model: &SbomReadModel) -> Result<String> {
        let mut output = String::new();
        self.render_required_sections(&mut output, model);
        self.render_optional_sections(&mut output, model);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        ComponentView, DependencyView, LicenseView, SeverityView,
    };
    use crate::i18n::Locale;
    use std::collections::HashMap;

    mod test_fixtures {
        use crate::application::read_models::{
            AbandonedPackageView, AbandonedPackagesReport, ComponentView, LicenseView,
            SbomMetadataView, SbomReadModel, SeverityView, VulnerabilityReportView,
            VulnerabilitySummary, VulnerabilityView,
        };
        use chrono::NaiveDate;

        pub(super) fn base_model() -> SbomReadModel {
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
                abandoned_packages: None,
            }
        }

        pub(super) fn with_vulnerabilities(severity: SeverityView) -> SbomReadModel {
            let mut model = base_model();
            let cvss_score = match severity {
                SeverityView::Critical => Some(9.8),
                SeverityView::High => Some(7.5),
                SeverityView::Medium => Some(5.0),
                SeverityView::Low => Some(3.1),
                SeverityView::None => None,
            };
            let fixed_version = match severity {
                SeverityView::Critical | SeverityView::High => Some("2.32.0".to_string()),
                _ => None,
            };
            model.vulnerabilities = Some(VulnerabilityReportView {
                actionable: vec![VulnerabilityView {
                    bom_ref: "vuln-001".to_string(),
                    id: "CVE-2024-1234".to_string(),
                    affected_component: "pkg:pypi/requests@2.31.0".to_string(),
                    affected_component_name: "requests".to_string(),
                    affected_version: "2.31.0".to_string(),
                    cvss_score,
                    cvss_vector: None,
                    severity,
                    fixed_version,
                    description: None,
                    source_url: None,
                }],
                informational: vec![],
                summary: VulnerabilitySummary {
                    total_count: 1,
                    affected_package_count: 1,
                },
            });
            model
        }

        /// Returns a model with one Critical-severity actionable vulnerability (CVE-2024-1234).
        pub(super) fn with_critical_vuln() -> SbomReadModel {
            with_vulnerabilities(SeverityView::Critical)
        }

        /// Returns a model with an empty vulnerability report (no actionable or informational).
        pub(super) fn with_empty_vuln_report() -> SbomReadModel {
            let mut model = base_model();
            model.vulnerabilities = Some(VulnerabilityReportView {
                actionable: vec![],
                informational: vec![],
                summary: VulnerabilitySummary {
                    total_count: 0,
                    affected_package_count: 0,
                },
            });
            model
        }

        /// Returns a model with two actionable vulnerabilities on the same package (Critical + High).
        pub(super) fn with_two_actionable_vulns() -> SbomReadModel {
            let mut model = base_model();
            model.vulnerabilities = Some(VulnerabilityReportView {
                actionable: vec![
                    make_vuln(
                        "CVE-2024-1234",
                        "pkg:pypi/requests@2.31.0",
                        "requests",
                        "2.31.0",
                        SeverityView::Critical,
                        Some(9.8_f32),
                        Some("2.32.0"),
                    ),
                    make_vuln(
                        "CVE-2024-5678",
                        "pkg:pypi/requests@2.31.0",
                        "requests",
                        "2.31.0",
                        SeverityView::High,
                        Some(7.5_f32),
                        None,
                    ),
                ],
                informational: vec![],
                summary: VulnerabilitySummary {
                    total_count: 2,
                    affected_package_count: 1,
                },
            });
            model
        }

        /// Returns a model with one Critical actionable and one Low informational vulnerability.
        pub(super) fn with_actionable_and_informational_vulns() -> SbomReadModel {
            let mut model = base_model();
            model.vulnerabilities = Some(VulnerabilityReportView {
                actionable: vec![make_vuln(
                    "CVE-2024-1234",
                    "pkg:pypi/requests@2.31.0",
                    "requests",
                    "2.31.0",
                    SeverityView::Critical,
                    Some(9.8_f32),
                    Some("2.32.0"),
                )],
                informational: vec![make_vuln(
                    "CVE-2024-5678",
                    "pkg:pypi/urllib3@1.26.0",
                    "urllib3",
                    "1.26.0",
                    SeverityView::Low,
                    Some(2.0_f32),
                    None,
                )],
                summary: VulnerabilitySummary {
                    total_count: 2,
                    affected_package_count: 2,
                },
            });
            model
        }

        pub(super) fn with_abandoned_packages(count: usize) -> SbomReadModel {
            let mut model = base_model();
            let packages = (0..count)
                .map(|i| AbandonedPackageView {
                    name: format!("old-pkg-{i}"),
                    version: "0.1.0".to_string(),
                    last_release_date: NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
                    days_inactive: 800 + i as i64,
                    is_direct: i % 2 == 0,
                })
                .collect();
            model.abandoned_packages = Some(AbandonedPackagesReport {
                packages,
                threshold_days: 730,
            });
            model
        }

        fn make_vuln(
            id: &str,
            affected_component: &str,
            name: &str,
            version: &str,
            severity: SeverityView,
            cvss_score: Option<f32>,
            fixed_version: Option<&str>,
        ) -> VulnerabilityView {
            VulnerabilityView {
                bom_ref: id.to_string(),
                id: id.to_string(),
                affected_component: affected_component.to_string(),
                affected_component_name: name.to_string(),
                affected_version: version.to_string(),
                cvss_score,
                cvss_vector: None,
                severity,
                fixed_version: fixed_version.map(str::to_string),
                description: None,
                source_url: None,
            }
        }
    }

    fn assert_ja_output_contains(
        model: &crate::application::read_models::SbomReadModel,
        expected: &str,
    ) {
        let formatter = MarkdownFormatter::new(Locale::Ja);
        let output = formatter.format(model).unwrap();
        assert!(
            output.contains(expected),
            "Expected ja output to contain {expected:?}, got:\n{output}"
        );
    }

    fn assert_ja_output_excludes(
        model: &crate::application::read_models::SbomReadModel,
        unexpected: &str,
    ) {
        let formatter = MarkdownFormatter::new(Locale::Ja);
        let output = formatter.format(model).unwrap();
        assert!(
            !output.contains(unexpected),
            "Expected ja output to NOT contain {unexpected:?}, got:\n{output}"
        );
    }

    fn assert_section_order(markdown: &str, sections: &[&str]) {
        let positions: Vec<usize> = sections
            .iter()
            .map(|section| {
                markdown.find(section).unwrap_or_else(|| {
                    panic!("Expected section {section:?} to be present, got:\n{markdown}")
                })
            })
            .collect();
        for (pos_pair, label_pair) in positions.windows(2).zip(sections.windows(2)) {
            assert!(
                pos_pair[0] < pos_pair[1],
                "Expected section {:?} (pos {}) to appear before {:?} (pos {})",
                label_pair[0],
                pos_pair[0],
                label_pair[1],
                pos_pair[1],
            );
        }
    }

    #[test]
    fn test_format_basic() {
        let model = test_fixtures::base_model();
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
        let mut model = test_fixtures::base_model();
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
        // Informational-only rendering (ℹ️Info section, "No vulnerabilities found above
        // threshold.") is covered by test_format_vulnerability_section_ordering, which uses
        // a model with both actionable and informational vulns.
        for severity in [SeverityView::Critical, SeverityView::Low] {
            let model = test_fixtures::with_vulnerabilities(severity);
            let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();

            assert!(
                markdown.contains("## Vulnerability Report"),
                "severity={severity:?}"
            );
            assert!(
                markdown.contains("### ⚠️Warning Found 1 vulnerability in 1 package."),
                "severity={severity:?}"
            );
            assert!(
                markdown
                    .contains("[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)"),
                "severity={severity:?}"
            );

            match severity {
                SeverityView::Critical => {
                    assert!(markdown.contains("🔴"));
                    assert!(markdown.contains("CRITICAL"));
                    assert!(markdown.contains("9.8"));
                    assert!(markdown.contains("2.32.0"));
                }
                SeverityView::Low => {
                    assert!(markdown.contains("🟢"));
                    assert!(markdown.contains("LOW"));
                    assert!(markdown.contains("3.1"));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_format_output_section_ordering() {
        let mut model = test_fixtures::base_model();
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );
        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();

        assert_section_order(
            &markdown,
            &[
                "## Summary",
                "# Software Bill of Materials (SBOM)",
                "## Component Inventory",
                "## Direct Dependencies",
                "## Transitive Dependencies",
            ],
        );
    }

    #[test]
    fn test_summary_vuln_skipped_note_when_no_network() {
        let model = test_fixtures::base_model(); // vulnerabilities: None

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("_Vulnerability check skipped._"));
    }

    #[test]
    fn test_summary_overall_action_required_when_critical_vuln() {
        let model = test_fixtures::with_critical_vuln();
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(markdown.contains("**Overall: Action required**"));
    }

    #[test]
    fn test_summary_overall_no_issues_when_clean() {
        let model = test_fixtures::base_model(); // no vulns, no license violations

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("**Overall: No issues found** ✅"));
    }

    #[test]
    fn test_format_vulnerability_section_ordering() {
        let model = test_fixtures::with_actionable_and_informational_vulns();
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();

        assert_section_order(
            &markdown,
            &[
                "**Found 2 vulnerabilities in 2 packages.**",
                "### ⚠️Warning",
                "### ℹ️Info",
                "*Vulnerability data provided by",
            ],
        );
    }

    // ===== Tests for --lang option (i18n) =====

    #[test]
    fn test_lang_ja_markdown_output_contains_japanese_headers() {
        let model = test_fixtures::base_model();
        assert_ja_output_contains(&model, "# ソフトウェア部品表 (SBOM)");
        assert_ja_output_contains(&model, "## コンポーネント一覧");
        assert_ja_output_excludes(&model, "# Software Bill of Materials (SBOM)");
        assert_ja_output_excludes(&model, "## Component Inventory");
    }

    #[test]
    fn test_lang_ja_markdown_output_contains_japanese_table_column() {
        let model = test_fixtures::base_model();
        assert_ja_output_contains(&model, "パッケージ");
        assert_ja_output_contains(&model, "バージョン");
        assert_ja_output_contains(&model, "ライセンス");
    }

    #[test]
    fn test_lang_en_markdown_output_unchanged() {
        let model = test_fixtures::base_model();
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
        let mut model = test_fixtures::base_model();
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );
        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        });
        assert_ja_output_contains(&model, "## 直接依存パッケージ");
        assert_ja_output_contains(&model, "## 間接依存パッケージ");
        assert_ja_output_excludes(&model, "## Direct Dependencies");
        assert_ja_output_excludes(&model, "## Transitive Dependencies");
        assert_ja_output_contains(&model, "### requestsの依存パッケージ");
        assert_ja_output_excludes(&model, "### Dependencies for requests");
    }

    #[test]
    fn test_lang_ja_section_descriptions_are_japanese() {
        let model = test_fixtures::base_model();
        assert_ja_output_contains(
            &model,
            "このプロジェクトに含まれるすべてのソフトウェアコンポーネントとライブラリの一覧です。",
        );
        assert_ja_output_excludes(&model, "A comprehensive list of all software components");
    }

    #[test]
    fn test_lang_ja_no_direct_deps_label_is_japanese() {
        let mut model = test_fixtures::base_model();
        model.dependencies = Some(DependencyView {
            direct: vec![],
            transitive: HashMap::new(),
        });
        assert_ja_output_contains(&model, "*直接依存パッケージなし*");
        assert_ja_output_excludes(&model, "*No direct dependencies*");
    }

    #[test]
    fn test_lang_ja_no_transitive_deps_label_is_japanese() {
        let mut model = test_fixtures::base_model();
        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive: HashMap::new(),
        });
        assert_ja_output_contains(&model, "*間接依存パッケージなし*");
        assert_ja_output_excludes(&model, "*No transitive dependencies*");
    }

    #[test]
    fn test_lang_ja_vuln_above_threshold_warning_is_japanese() {
        let model = test_fixtures::with_empty_vuln_report();
        assert_ja_output_contains(
            &model,
            "### ⚠️警告 閾値を超える脆弱性は見つかりませんでした。",
        );
        assert_ja_output_excludes(
            &model,
            "### ⚠️Warning No vulnerabilities found above threshold.",
        );
    }

    #[test]
    fn test_lang_ja_actionable_vuln_count_is_japanese() {
        let model = test_fixtures::with_critical_vuln();
        assert_ja_output_contains(
            &model,
            "### ⚠️警告 1件の脆弱性が1個のパッケージで見つかりました。",
        );
        assert_ja_output_excludes(&model, "### ⚠️Warning Found");
    }

    #[test]
    fn test_lang_ja_osv_attribution_is_japanese() {
        let model = test_fixtures::with_empty_vuln_report();
        assert_ja_output_contains(&model, "*脆弱性データは [OSV](https://osv.dev) より CC-BY 4.0 ライセンスの下で提供されています*");
        assert_ja_output_excludes(&model, "*Vulnerability data provided by");
    }

    #[test]
    fn test_lang_ja_no_license_violations_is_japanese() {
        use crate::application::read_models::{LicenseComplianceSummary, LicenseComplianceView};

        let mut model = test_fixtures::base_model();
        model.license_compliance = Some(LicenseComplianceView {
            has_violations: false,
            violations: vec![],
            warnings: vec![],
            summary: LicenseComplianceSummary {
                violation_count: 0,
                warning_count: 0,
            },
        });
        assert_ja_output_contains(&model, "**ライセンス違反は見つかりませんでした。**");
        assert_ja_output_excludes(&model, "**No license violations found.**");
    }

    #[test]
    fn test_lang_ja_license_violations_count_is_japanese() {
        use crate::application::read_models::{
            LicenseComplianceSummary, LicenseComplianceView, LicenseViolationView,
        };

        let mut model = test_fixtures::base_model();
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

        assert_ja_output_contains(&model, "**4 件のライセンス違反が見つかりました。**");
        assert_ja_output_excludes(&model, "license violations found");
    }

    #[test]
    fn test_lang_ja_resolution_guide_action_is_japanese() {
        use crate::application::read_models::{
            IntroducedByView, ResolutionEntryView, ResolutionGuideView, UpgradeEntryView,
            UpgradeRecommendationView,
        };

        let mut model = test_fixtures::base_model();
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
                dependency_chains: vec![],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Upgradable {
                direct_dep: "requests".to_string(),
                target_version: "2.32.3".to_string(),
                transitive_dep: "urllib3".to_string(),
                resolved_version: "2.2.1".to_string(),
                vulnerability_id: "CVE-2024-XXXXX".to_string(),
            }],
        });

        assert_ja_output_contains(&model, "推奨アクション");
        assert_ja_output_contains(
            &model,
            "⬆️ requestsを2.32.3にアップグレード（urllib3が2.2.1に解決）",
        );
        assert_ja_output_excludes(&model, "⬆️ Upgrade");
    }

    #[test]
    fn test_lang_ja_with_vulnerabilities_contains_japanese_vuln_headers() {
        let model = test_fixtures::with_critical_vuln();
        // CVE ID remains in its original form regardless of locale
        assert_ja_output_contains(&model, "## 脆弱性レポート");
        assert_ja_output_excludes(&model, "## Vulnerability Report");
        assert_ja_output_contains(&model, "CVE-2024-1234");
    }

    #[test]
    fn test_lang_ja_vuln_summary_is_japanese() {
        let model = test_fixtures::with_two_actionable_vulns();
        assert_ja_output_contains(&model, "**2件の脆弱性が1個のパッケージで見つかりました。**");
        assert_ja_output_excludes(&model, "**Found");
    }

    #[test]
    fn test_format_license_falls_back_to_name_when_spdx_id_is_none() {
        let mut model = test_fixtures::base_model();
        model.components.push(ComponentView {
            bom_ref: "pkg:pypi/somelib@1.0.0".to_string(),
            name: "somelib".to_string(),
            version: "1.0.0".to_string(),
            purl: "pkg:pypi/somelib@1.0.0".to_string(),
            license: Some(LicenseView {
                spdx_id: None,
                name: "Some Custom License".to_string(),
            }),
            description: None,
            sha256_hash: None,
            is_direct_dependency: false,
        });

        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Some Custom License"));
    }

    // ===== Abandoned packages section tests =====

    #[test]
    fn test_abandoned_section_present_when_report_provided() {
        let model = test_fixtures::with_abandoned_packages(2);
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(markdown.contains("## Abandoned Packages"));
        assert!(markdown.contains("old-pkg-0"));
        assert!(markdown.contains("old-pkg-1"));
    }

    #[test]
    fn test_abandoned_section_absent_when_none() {
        let model = test_fixtures::base_model(); // abandoned_packages: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## Abandoned Packages"));
    }

    #[test]
    fn test_abandoned_empty_report_renders_no_packages_message() {
        let mut model = test_fixtures::base_model();
        model.abandoned_packages = Some(crate::application::read_models::AbandonedPackagesReport {
            packages: vec![],
            threshold_days: 730,
        });
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(markdown.contains("## Abandoned Packages"));
        assert!(markdown.contains("No abandoned packages detected."));
        assert!(!markdown.contains("| Package | Version | Last Release |"));
    }

    #[test]
    fn test_abandoned_section_order_after_license_before_resolution_guide() {
        use crate::application::read_models::{
            AbandonedPackageView, AbandonedPackagesReport, IntroducedByView,
            LicenseComplianceSummary, LicenseComplianceView, ResolutionEntryView,
            ResolutionGuideView,
        };
        use chrono::NaiveDate;

        let mut model = test_fixtures::base_model();
        model.license_compliance = Some(LicenseComplianceView {
            has_violations: false,
            violations: vec![],
            warnings: vec![],
            summary: LicenseComplianceSummary {
                violation_count: 0,
                warning_count: 0,
            },
        });
        model.abandoned_packages = Some(AbandonedPackagesReport {
            packages: vec![AbandonedPackageView {
                name: "stale-lib".to_string(),
                version: "1.0.0".to_string(),
                last_release_date: NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
                days_inactive: 900,
                is_direct: true,
            }],
            threshold_days: 730,
        });
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                fixed_version: Some("2.32.0".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-0001".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
                dependency_chains: vec![],
            }],
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert_section_order(
            &markdown,
            &[
                "## License Compliance Report",
                "## Abandoned Packages",
                "## Vulnerability Resolution Guide",
            ],
        );
    }

    #[test]
    fn test_abandoned_section_ja_locale() {
        let model = test_fixtures::with_abandoned_packages(1);
        let markdown = MarkdownFormatter::new(Locale::Ja).format(&model).unwrap();
        assert!(markdown.contains("## 廃止パッケージ"));
        assert!(markdown.contains("old-pkg-0"));
    }

    #[test]
    fn test_summary_shows_abandoned_skipped_when_none() {
        let model = test_fixtures::base_model();
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(markdown.contains("_Abandoned package check skipped._"));
    }

    #[test]
    fn test_summary_shows_abandoned_row_when_report_present() {
        let model = test_fixtures::with_abandoned_packages(2);
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(markdown.contains("| Abandoned packages | 2 | ⚠️ |"));
        assert!(!markdown.contains("_Abandoned package check skipped._"));
    }
}
