mod helpers;
mod links;
mod sections;
pub(super) mod table;
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
            &model.applied_group_filter,
        );
        sections::header::render(self.messages, output);
        sections::components::render(
            self.messages,
            self.verified_packages.as_ref(),
            output,
            &model.components,
        );
    }

    /// Renders the conditional sections when present: dependencies, dependency
    /// tree, dependency explanation, vulnerabilities, license compliance,
    /// abandoned packages, non-PyPI packages, Python compatibility, and
    /// resolution guide.
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
        if let Some(tree) = &model.dependency_tree {
            sections::dependency_tree::render(self.messages, output, tree);
        }
        if let Some(view) = &model.explain_view {
            sections::explain::render(self.messages, output, view);
        }
        if let Some(vulns) = &model.vulnerabilities {
            vuln_render::render_vulnerabilities(
                self.messages,
                self.verified_packages.as_ref(),
                output,
                vulns,
                model.baseline_suppressed_count,
            );
        }
        if let Some(compliance) = &model.license_compliance {
            sections::license_compliance::render(self.messages, output, compliance);
        }
        if let Some(report) = &model.abandoned_packages {
            sections::abandoned_packages::render(self.messages, output, report);
        }
        if let Some(report) = &model.non_pypi_packages {
            if !report.is_empty() {
                sections::non_pypi_packages::render(self.messages, output, report);
            }
        }
        if let Some(report) = &model.python_compatibility {
            sections::python_compatibility::render(self.messages, output, report);
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
    use crate::application::read_models::{DependencyView, SeverityView};
    use crate::i18n::Locale;
    use std::collections::HashMap;

    mod test_fixtures {
        use crate::application::read_models::{
            ComponentView, LicenseView, SbomMetadataView, SbomReadModel, SeverityView,
            VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
        };

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
                non_pypi_packages: None,
                python_compatibility: None,
                explain_view: None,
                dependency_tree: None,
                baseline_suppressed_count: 0,
                applied_group_filter: vec![],
            }
        }

        /// Returns a model with one Critical-severity actionable vulnerability (CVE-2024-1234).
        pub(super) fn with_critical_vuln() -> SbomReadModel {
            let mut model = base_model();
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
                    epss_percentile: None,
                    in_kev: None,
                    is_malicious: false,
                }],
                informational: vec![],
                summary: VulnerabilitySummary {
                    total_count: 1,
                    affected_package_count: 1,
                },
            });
            model
        }
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

    // ===== Abandoned packages section tests =====

    #[test]
    fn test_abandoned_section_absent_when_none() {
        let model = test_fixtures::base_model(); // abandoned_packages: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## Abandoned Packages"));
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
                epss_percentile: None,
                in_kev: None,
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

    // ===== Non-PyPI packages section tests =====

    fn with_non_pypi_packages(
        packages: Vec<crate::application::read_models::NonPyPiPackageView>,
    ) -> crate::application::read_models::SbomReadModel {
        use crate::application::read_models::NonPyPiPackagesReport;
        let mut model = test_fixtures::base_model();
        model.non_pypi_packages = Some(NonPyPiPackagesReport { packages });
        model
    }

    #[test]
    fn test_non_pypi_section_absent_when_none() {
        let model = test_fixtures::base_model(); // non_pypi_packages: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## ⚠️ Non-PyPI Package Sources"));
    }

    #[test]
    fn test_non_pypi_section_absent_when_empty() {
        let model = with_non_pypi_packages(vec![]);
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## ⚠️ Non-PyPI Package Sources"));
    }

    #[test]
    fn test_non_pypi_section_order_after_abandoned_before_resolution_guide() {
        use crate::application::read_models::{
            AbandonedPackageView, AbandonedPackagesReport, IntroducedByView, NonPyPiPackageView,
            ResolutionEntryView, ResolutionGuideView,
        };
        use chrono::NaiveDate;

        let mut model = with_non_pypi_packages(vec![NonPyPiPackageView {
            name: "dev-tool".to_string(),
            version: "1.0.0".to_string(),
            source_label: "Git".to_string(),
            source_location: "https://github.com/example/repo".to_string(),
            is_direct: true,
        }]);
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
                epss_percentile: None,
                in_kev: None,
            }],
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert_section_order(
            &markdown,
            &[
                "## Abandoned Packages",
                "## ⚠️ Non-PyPI Package Sources",
                "## Vulnerability Resolution Guide",
            ],
        );
    }

    // ===== Python compatibility section tests =====

    #[test]
    fn test_python_compat_section_absent_when_none() {
        let model = test_fixtures::base_model(); // python_compatibility: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("Python 3"));
        assert!(!markdown.contains("Compatibility Issues"));
        assert!(!markdown.contains("Compatibility"));
    }

    #[test]
    fn test_python_compat_section_order_after_non_pypi_before_resolution_guide() {
        use crate::application::read_models::{
            IntroducedByView, NonPyPiPackageView, NonPyPiPackagesReport, PythonCompatibilityReport,
            PythonIncompatibilityView, ResolutionEntryView, ResolutionGuideView,
        };

        let mut model = test_fixtures::base_model();
        model.non_pypi_packages = Some(NonPyPiPackagesReport {
            packages: vec![NonPyPiPackageView {
                name: "dev-tool".to_string(),
                version: "1.0.0".to_string(),
                source_label: "Git".to_string(),
                source_location: "https://github.com/example/repo".to_string(),
                is_direct: true,
            }],
        });
        model.python_compatibility = Some(PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![PythonIncompatibilityView {
                name: "legacy-lib".to_string(),
                version: "1.0.0".to_string(),
                requires_python: Some(">=3.8,<3.12".to_string()),
                is_direct: true,
            }],
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
                epss_percentile: None,
                in_kev: None,
            }],
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert_section_order(
            &markdown,
            &[
                "## ⚠️ Non-PyPI Package Sources",
                "## ⚠️ Python",
                "## Vulnerability Resolution Guide",
            ],
        );
    }

    // ===== Dependency explanation section tests =====

    #[test]
    fn test_explain_section_absent_when_none() {
        let model = test_fixtures::base_model(); // explain_view: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## Dependency Explanation"));
    }

    #[test]
    fn test_explain_section_order_after_dependencies_before_vulnerabilities() {
        use crate::application::read_models::ExplainView;

        let mut model = test_fixtures::with_critical_vuln();
        let mut transitive = HashMap::new();
        transitive.insert(
            "pkg:pypi/requests@2.31.0".to_string(),
            vec!["pkg:pypi/urllib3@1.26.0".to_string()],
        );
        model.dependencies = Some(DependencyView {
            direct: vec!["pkg:pypi/requests@2.31.0".to_string()],
            transitive,
        });
        model.explain_view = Some(ExplainView {
            target_package: "urllib3".to_string(),
            found: true,
            is_direct: false,
            paths: vec![vec!["requests".to_string(), "urllib3".to_string()]],
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert_section_order(
            &markdown,
            &[
                "## Transitive Dependencies",
                "## Dependency Explanation",
                "## Vulnerability Report",
            ],
        );
    }

    #[test]
    fn test_dependency_tree_section_absent_when_none() {
        let model = test_fixtures::base_model(); // dependency_tree: None
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(!markdown.contains("## Dependency Tree"));
    }

    #[test]
    fn test_dependency_tree_section_order_after_dependencies_before_explain() {
        use crate::application::read_models::{
            DependencyTreeNodeView, DependencyTreeView, ExplainView,
        };

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
        model.dependency_tree = Some(DependencyTreeView {
            roots: vec![DependencyTreeNodeView {
                name: "requests".to_string(),
                version: Some("2.31.0".to_string()),
                children: vec![],
                truncated: false,
            }],
            max_depth: 3,
        });
        model.explain_view = Some(ExplainView {
            target_package: "urllib3".to_string(),
            found: true,
            is_direct: false,
            paths: vec![vec!["requests".to_string(), "urllib3".to_string()]],
        });

        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert_section_order(
            &markdown,
            &[
                "## Transitive Dependencies",
                "## Dependency Tree",
                "## Dependency Explanation",
            ],
        );
    }

    // ===== Baseline suppression footnote tests =====

    #[test]
    fn test_baseline_footnote_present_when_suppressed_count_positive() {
        // Integration check: the formatter must pass the model's count through to
        // the vulnerability renderer (footnote text itself is tested in vuln_render.rs).
        let mut model = test_fixtures::with_critical_vuln();
        model.baseline_suppressed_count = 3;
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(
            markdown.contains("_Note: 3 previously-baselined finding(s) suppressed._"),
            "Expected baseline footnote, got:\n{markdown}"
        );
    }

    #[test]
    fn test_baseline_footnote_absent_when_no_vuln_section() {
        let mut model = test_fixtures::base_model();
        model.baseline_suppressed_count = 5;
        let markdown = MarkdownFormatter::new(Locale::En).format(&model).unwrap();
        assert!(
            !markdown.contains("previously-baselined"),
            "Should not contain baseline footnote when no vulnerability section"
        );
    }
}
