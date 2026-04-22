use crate::application::read_models::{ResolutionGuideView, UpgradeRecommendationView};
use crate::i18n::Messages;

/// Renders the vulnerability resolution guide section as a Markdown table.
///
/// When `upgrade_recommendations` is `Some`, an extra "Recommended Action" column is
/// appended to each row, showing whether an upgrade path exists for the affected
/// direct dependency. When `None`, that column is omitted entirely.
pub(in super::super) fn render(
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

    // Build column list — optional "Recommended Action" column included only when
    // upgrade_recommendations is provided.
    let mut columns: Vec<&str> = vec![
        messages.col_vulnerable_package,
        messages.col_current,
        messages.col_fixed_version,
        messages.col_severity,
        messages.col_introduced_by,
    ];
    if upgrade_recommendations.is_some() {
        columns.push(messages.col_recommended_action);
    }
    columns.push(messages.col_vuln_id);

    output.push_str(&format!("| {} |\n", columns.join(" | ")));
    output.push_str(&super::super::table::make_separator(&columns));

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

        // Compute the optional action cell before building the row.
        let action = upgrade_recommendations.map(|recommendations| {
            super::super::helpers::find_upgrade_action(
                messages,
                recommendations,
                &entry.vulnerability_id,
                &entry.introduced_by,
            )
        });

        let mut cells: Vec<String> = vec![
            super::super::table::escape_markdown_table_cell(&entry.vulnerable_package),
            super::super::table::escape_markdown_table_cell(&entry.current_version),
            super::super::table::escape_markdown_table_cell(fixed),
            format!("{} {}", severity_emoji, entry.severity.as_str()),
            super::super::table::escape_markdown_table_cell(&introduced_by),
        ];
        if let Some(ref act) = action {
            cells.push(super::super::table::escape_markdown_table_cell(act));
        }
        cells.push(super::super::links::vulnerability_id_to_link(
            &entry.vulnerability_id,
        ));

        output.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    output.push('\n');

    // Dependency Chains subsection: only render entries that contain at least
    // one multi-hop chain (len > 2). A 2-element chain means the vulnerable
    // package is a direct dependency, which the main table already makes
    // obvious, so listing it here would be noise.
    let has_multi_hop = guide
        .entries
        .iter()
        .any(|e| e.dependency_chains.iter().any(|c| c.len() > 2));

    if has_multi_hop {
        output.push_str(messages.section_dependency_chains);
        output.push_str("\n\n");

        for entry in &guide.entries {
            if !entry.dependency_chains.iter().any(|c| c.len() > 2) {
                continue;
            }

            output.push_str(&format!(
                "**`{} {}`** — {} ({})\n",
                entry.vulnerable_package,
                entry.current_version,
                entry.vulnerability_id,
                entry.severity.as_str(),
            ));

            for chain in entry.dependency_chains.iter().filter(|c| c.len() > 2) {
                let last_idx = chain.len() - 1;
                let rendered = chain
                    .iter()
                    .enumerate()
                    .map(|(i, node)| {
                        if i == last_idx {
                            format!("**`{} {}`** ⚠️", node, entry.current_version)
                        } else {
                            format!("`{}`", node)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" → ");
                output.push_str(&format!("- {}\n", rendered));
            }
            output.push('\n');
        }
    }
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
                dependency_chains: vec![],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
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
                dependency_chains: vec![],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("requests (2.31.0), httpx (0.25.0)"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_empty() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView { entries: vec![] });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("## Vulnerability Resolution Guide"));
    }

    #[test]
    fn test_resolution_guide_omitted_when_none() {
        let model = create_test_read_model();
        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
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
                dependency_chains: vec![],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
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

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
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
                dependency_chains: vec![],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::Unresolvable {
                reason: "latest httpx still pins idna < 3.7".to_string(),
                vulnerability_id: "GHSA-ZZZZZ".to_string(),
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
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
                dependency_chains: vec![],
            }],
        });
        model.upgrade_recommendations = Some(UpgradeRecommendationView {
            entries: vec![UpgradeEntryView::SimulationFailed {
                direct_dep: "requests".to_string(),
                error: "dependency resolution timed out".to_string(),
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("Recommended Action"));
        assert!(markdown.contains("❓ Could not analyze: dependency resolution timed out"));
    }

    #[test]
    fn test_dependency_chains_subsection_rendered_when_multi_hop() {
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
                dependency_chains: vec![vec![
                    "requests".to_string(),
                    "httpcore".to_string(),
                    "urllib3".to_string(),
                ]],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("### Dependency Chains"));
        assert!(markdown.contains("**`urllib3 1.26.15`** — CVE-2024-XXXXX (HIGH)"));
        assert!(markdown.contains("- `requests` → `httpcore` → **`urllib3 1.26.15`** ⚠️"));
    }

    #[test]
    fn test_dependency_chains_subsection_omitted_when_direct_only() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![ResolutionEntryView {
                vulnerable_package: "requests".to_string(),
                current_version: "2.31.0".to_string(),
                fixed_version: Some(">= 2.32.0".to_string()),
                severity: SeverityView::High,
                vulnerability_id: "CVE-2024-ABCDE".to_string(),
                introduced_by: vec![IntroducedByView {
                    package_name: "requests".to_string(),
                    version: "2.31.0".to_string(),
                }],
                dependency_chains: vec![vec!["requests".to_string(), "requests".to_string()]],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("## Vulnerability Resolution Guide"));
        assert!(!markdown.contains("### Dependency Chains"));
    }

    #[test]
    fn test_dependency_chains_subsection_multiple_paths_as_bullets() {
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
                dependency_chains: vec![
                    vec![
                        "requests".to_string(),
                        "httpcore".to_string(),
                        "urllib3".to_string(),
                    ],
                    vec![
                        "httpx".to_string(),
                        "httpcore".to_string(),
                        "urllib3".to_string(),
                    ],
                ],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("- `requests` → `httpcore` → **`urllib3 1.26.15`** ⚠️"));
        assert!(markdown.contains("- `httpx` → `httpcore` → **`urllib3 1.26.15`** ⚠️"));
    }

    #[test]
    fn test_dependency_chains_subsection_filters_direct_only_entries() {
        let mut model = create_test_read_model();
        model.resolution_guide = Some(ResolutionGuideView {
            entries: vec![
                ResolutionEntryView {
                    vulnerable_package: "requests".to_string(),
                    current_version: "2.31.0".to_string(),
                    fixed_version: Some(">= 2.32.0".to_string()),
                    severity: SeverityView::High,
                    vulnerability_id: "CVE-DIRECT".to_string(),
                    introduced_by: vec![IntroducedByView {
                        package_name: "requests".to_string(),
                        version: "2.31.0".to_string(),
                    }],
                    dependency_chains: vec![vec!["requests".to_string(), "requests".to_string()]],
                },
                ResolutionEntryView {
                    vulnerable_package: "urllib3".to_string(),
                    current_version: "1.26.15".to_string(),
                    fixed_version: Some(">= 2.0.7".to_string()),
                    severity: SeverityView::High,
                    vulnerability_id: "CVE-TRANSITIVE".to_string(),
                    introduced_by: vec![IntroducedByView {
                        package_name: "requests".to_string(),
                        version: "2.31.0".to_string(),
                    }],
                    dependency_chains: vec![vec![
                        "requests".to_string(),
                        "httpcore".to_string(),
                        "urllib3".to_string(),
                    ]],
                },
            ],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("### Dependency Chains"));
        assert!(!markdown.contains("**`requests 2.31.0`** — CVE-DIRECT"));
        assert!(markdown.contains("**`urllib3 1.26.15`** — CVE-TRANSITIVE (HIGH)"));
    }

    #[test]
    fn test_dependency_chains_subsection_ja_locale() {
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
                dependency_chains: vec![vec![
                    "requests".to_string(),
                    "httpcore".to_string(),
                    "urllib3".to_string(),
                ]],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::Ja);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("### 依存チェーン"));
        assert!(!markdown.contains("### Dependency Chains"));
        assert!(markdown.contains("- `requests` → `httpcore` → **`urllib3 1.26.15`** ⚠️"));
        assert!(markdown.contains("(HIGH)"));
    }

    #[test]
    fn test_dependency_chains_subsection_omitted_when_chains_empty() {
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
                dependency_chains: vec![],
            }],
        });

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(markdown.contains("## Vulnerability Resolution Guide"));
        assert!(!markdown.contains("### Dependency Chains"));
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
                dependency_chains: vec![],
            }],
        });
        // upgrade_recommendations is None (default in test model)

        let formatter = super::super::super::MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        assert!(!markdown.contains("Recommended Action"));
        assert!(markdown.contains("## Vulnerability Resolution Guide"));
    }
}
