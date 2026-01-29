use crate::application::read_models::{
    ComponentView, DependencyView, SbomReadModel, VulnerabilityReportView, VulnerabilitySummary,
    VulnerabilityView,
};
use crate::ports::outbound::SbomFormatter;
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

/// Markdown table header for package information
const TABLE_HEADER: &str = "| Package | Version | License | Description |\n";

/// Markdown table separator line
const TABLE_SEPARATOR: &str = "|---------|---------|---------|-------------|\n";

/// Markdown table header for vulnerability information
const VULN_TABLE_HEADER: &str =
    "| Package | Current Version | Fixed Version | CVSS | Severity | CVE ID |\n";

/// Markdown table separator line for vulnerability table
const VULN_TABLE_SEPARATOR: &str =
    "|---------|-----------------|---------------|------|----------|--------|\n";

/// MarkdownFormatter adapter for generating detailed Markdown SBOM with dependency information
///
/// This adapter implements the SbomFormatter port for Markdown format,
/// including dependency graph visualization.
pub struct MarkdownFormatter {
    /// When Some, only packages in this set get PyPI hyperlinks.
    /// When None, all packages get PyPI hyperlinks (default behavior).
    verified_packages: Option<HashSet<String>>,
}

impl MarkdownFormatter {
    pub fn new() -> Self {
        Self {
            verified_packages: None,
        }
    }

    /// Creates a new MarkdownFormatter with a set of verified PyPI packages.
    /// Only packages in the set will get hyperlinks; others render as plain text.
    pub fn with_verified_packages(verified_packages: HashSet<String>) -> Self {
        Self {
            verified_packages: Some(verified_packages),
        }
    }

    /// Escapes pipe characters and newlines for safe Markdown table rendering
    fn escape_markdown_table_cell(text: &str) -> String {
        text.replace('|', "\\|").replace('\n', " ")
    }

    /// Normalize package name for PyPI URL (lowercase, replace _ with -)
    fn normalize_for_pypi(name: &str) -> String {
        name.to_lowercase().replace('_', "-")
    }

    /// Generate a Markdown hyperlink to the package's PyPI page
    fn package_to_pypi_link(name: &str) -> String {
        let normalized = Self::normalize_for_pypi(name);
        format!(
            "[{}](https://pypi.org/project/{}/)",
            Self::escape_markdown_table_cell(name),
            normalized
        )
    }

    /// Format a package name as a PyPI link or plain text based on verification results.
    /// - If no verification was performed (verified_packages is None), always generate a link.
    /// - If verification was performed, only generate a link for verified packages.
    fn format_package_name(&self, name: &str) -> String {
        match &self.verified_packages {
            None => Self::package_to_pypi_link(name),
            Some(verified) => {
                if verified.contains(name) {
                    Self::package_to_pypi_link(name)
                } else {
                    Self::escape_markdown_table_cell(name)
                }
            }
        }
    }
}

/// Helper methods for rendering sections
impl MarkdownFormatter {
    /// Renders the header section
    fn render_header(&self, output: &mut String) {
        output.push_str("# Software Bill of Materials (SBOM)\n\n");
    }

    /// Renders the components section
    fn render_components(&self, output: &mut String, components: &[ComponentView]) {
        output.push_str("## Component Inventory\n\n");
        output.push_str(
            "A comprehensive list of all software components and libraries included in this project.\n\n",
        );
        output.push_str(TABLE_HEADER);
        output.push_str(TABLE_SEPARATOR);

        for component in components {
            let license = component
                .license
                .as_ref()
                .map(|l| l.name.as_str())
                .unwrap_or("N/A");
            let description = component.description.as_deref().unwrap_or("");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                self.format_package_name(&component.name),
                Self::escape_markdown_table_cell(&component.version),
                Self::escape_markdown_table_cell(license),
                Self::escape_markdown_table_cell(description)
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
        output.push_str("## Direct Dependencies\n\n");
        output.push_str(
            "Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).\n\n",
        );

        if !deps.direct.is_empty() {
            output.push_str(TABLE_HEADER);
            output.push_str(TABLE_SEPARATOR);

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
                        self.format_package_name(&component.name),
                        Self::escape_markdown_table_cell(&component.version),
                        Self::escape_markdown_table_cell(license),
                        Self::escape_markdown_table_cell(description)
                    ));
                }
            }
            output.push('\n');
        } else {
            output.push_str("*No direct dependencies*\n\n");
        }

        // Transitive Dependencies section
        output.push_str("## Transitive Dependencies\n\n");
        output.push_str("Secondary dependencies introduced by the primary packages.\n\n");

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

                    output.push_str(&format!("### Dependencies for {}\n\n", parent_name));
                    output.push_str(TABLE_HEADER);
                    output.push_str(TABLE_SEPARATOR);

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
                                self.format_package_name(&component.name),
                                Self::escape_markdown_table_cell(&component.version),
                                Self::escape_markdown_table_cell(license),
                                Self::escape_markdown_table_cell(description)
                            ));
                        }
                    }
                    output.push('\n');
                }
            }
        } else {
            output.push_str("*No transitive dependencies*\n\n");
        }
    }

    /// Renders the vulnerabilities section
    fn render_vulnerabilities(&self, output: &mut String, vulns: &VulnerabilityReportView) {
        output.push_str("\n## Vulnerability Report\n\n");

        // Summary section
        self.render_vulnerability_summary(output, &vulns.summary);

        // Actionable vulnerabilities (warning section)
        if vulns.actionable.is_empty() {
            output.push_str("### ⚠️Warning No vulnerabilities found above threshold.\n\n");
        } else {
            self.render_actionable_vulnerabilities(output, &vulns.actionable);
        }

        // Informational vulnerabilities
        if !vulns.informational.is_empty() {
            self.render_informational_vulnerabilities(output, &vulns.informational);
        }

        // Attribution
        output.push_str("\n---\n\n");
        output
            .push_str("*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*\n");
    }

    /// Renders vulnerability summary statistics
    fn render_vulnerability_summary(&self, output: &mut String, summary: &VulnerabilitySummary) {
        output.push_str(&format!(
            "**Found {} {} in {} {}.**\n\n",
            summary.total_count,
            if summary.total_count == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            summary.affected_package_count,
            if summary.affected_package_count == 1 {
                "package"
            } else {
                "packages"
            }
        ));
    }

    /// Renders the warning section for actionable vulnerabilities
    fn render_actionable_vulnerabilities(&self, output: &mut String, vulns: &[VulnerabilityView]) {
        let total_vulns = vulns.len();
        let unique_packages = Self::count_unique_packages(vulns);

        output.push_str(&format!(
            "### ⚠️Warning Found {} {} in {} {}.\n\n",
            total_vulns,
            if total_vulns == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            unique_packages,
            if unique_packages == 1 {
                "package"
            } else {
                "packages"
            }
        ));

        output.push_str(VULN_TABLE_HEADER);
        output.push_str(VULN_TABLE_SEPARATOR);

        // Sort by severity (Critical first)
        let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.iter().collect();
        sorted_vulns.sort_by(|a, b| a.severity.cmp(&b.severity));

        for vuln in sorted_vulns {
            self.render_vulnerability_row(output, vuln);
        }
        output.push('\n');
    }

    /// Renders the info section for informational vulnerabilities
    fn render_informational_vulnerabilities(
        &self,
        output: &mut String,
        vulns: &[VulnerabilityView],
    ) {
        let total_vulns = vulns.len();
        let unique_packages = Self::count_unique_packages(vulns);

        output.push_str(&format!(
            "### ℹ️Info Found {} {} in {} {}.\n\n",
            total_vulns,
            if total_vulns == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            unique_packages,
            if unique_packages == 1 {
                "package"
            } else {
                "packages"
            }
        ));

        output.push_str(VULN_TABLE_HEADER);
        output.push_str(VULN_TABLE_SEPARATOR);

        let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.iter().collect();
        sorted_vulns.sort_by(|a, b| a.severity.cmp(&b.severity));

        for vuln in sorted_vulns {
            self.render_vulnerability_row(output, vuln);
        }
    }

    /// Counts unique affected packages from a list of vulnerability views
    fn count_unique_packages(vulns: &[VulnerabilityView]) -> usize {
        let unique: std::collections::HashSet<&str> = vulns
            .iter()
            .map(|v| v.affected_component.as_str())
            .collect();
        unique.len().max(1)
    }

    /// Renders a single vulnerability row
    fn render_vulnerability_row(&self, output: &mut String, vuln: &VulnerabilityView) {
        let cvss_display = vuln
            .cvss_score
            .map_or("N/A".to_string(), |s| format!("{:.1}", s));
        let fixed_version = vuln.fixed_version.as_deref().unwrap_or("N/A");
        let severity_emoji = match vuln.severity {
            crate::application::read_models::SeverityView::Critical => "🔴",
            crate::application::read_models::SeverityView::High => "🟠",
            crate::application::read_models::SeverityView::Medium => "🟡",
            crate::application::read_models::SeverityView::Low => "🟢",
            crate::application::read_models::SeverityView::None => "⚪",
        };

        output.push_str(&format!(
            "| {} | {} | {} | {} | {} {} | {} |\n",
            self.format_package_name(&vuln.affected_component_name),
            Self::escape_markdown_table_cell(&vuln.affected_version),
            Self::escape_markdown_table_cell(fixed_version),
            cvss_display,
            severity_emoji,
            vuln.severity.as_str(),
            Self::escape_markdown_table_cell(&vuln.id),
        ));
    }
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
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

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        LicenseView, SbomMetadataView, SeverityView, VulnerabilitySummary,
    };
    use std::collections::HashMap;

    fn create_test_read_model() -> SbomReadModel {
        SbomReadModel {
            metadata: SbomMetadataView {
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                tool_name: "uv-sbom".to_string(),
                tool_version: "1.0.0".to_string(),
                serial_number: "urn:uuid:test-123".to_string(),
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
        }
    }

    #[test]
    fn test_escape_markdown_table_cell() {
        let input = "Text with | pipe and\nnewline";
        let escaped = MarkdownFormatter::escape_markdown_table_cell(input);
        assert_eq!(escaped, "Text with \\| pipe and newline");
    }

    #[test]
    fn test_format_basic() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new();

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

        let formatter = MarkdownFormatter::new();
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

        let formatter = MarkdownFormatter::new();
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Vulnerability Report"));
        assert!(markdown.contains("### ⚠️Warning Found 1 vulnerability in 1 package."));
        assert!(markdown.contains("CVE-2024-1234"));
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

        let formatter = MarkdownFormatter::new();
        let result = formatter.format(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("### ⚠️Warning No vulnerabilities found above threshold."));
        assert!(markdown.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(markdown.contains("CVE-2024-5678"));
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

        let formatter = MarkdownFormatter::new();
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

    // ============================================================
    // Vulnerability rendering unit tests
    // ============================================================

    #[test]
    fn test_render_vulnerability_summary() {
        let formatter = MarkdownFormatter::new();
        let summary = VulnerabilitySummary {
            total_count: 3,
            actionable_count: 2,
            informational_count: 1,
            affected_package_count: 2,
        };

        let mut output = String::new();
        formatter.render_vulnerability_summary(&mut output, &summary);

        assert!(output.contains("**Found 3 vulnerabilities in 2 packages.**"));
    }

    #[test]
    fn test_render_vulnerability_summary_singular() {
        let formatter = MarkdownFormatter::new();
        let summary = VulnerabilitySummary {
            total_count: 1,
            actionable_count: 1,
            informational_count: 0,
            affected_package_count: 1,
        };

        let mut output = String::new();
        formatter.render_vulnerability_summary(&mut output, &summary);

        assert!(output.contains("**Found 1 vulnerability in 1 package.**"));
    }

    #[test]
    fn test_render_actionable_vulnerabilities() {
        let formatter = MarkdownFormatter::new();
        let vulns = vec![
            VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1111".to_string(),
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
                id: "CVE-2024-2222".to_string(),
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
        ];

        let mut output = String::new();
        formatter.render_actionable_vulnerabilities(&mut output, &vulns);

        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 1 package."));
        assert!(output.contains("CVE-2024-1111"));
        assert!(output.contains("CVE-2024-2222"));
        assert!(output.contains("🔴"));
        assert!(output.contains("🟠"));
        assert!(output.contains("9.8"));
        assert!(output.contains("7.5"));
    }

    #[test]
    fn test_render_informational_vulnerabilities() {
        let formatter = MarkdownFormatter::new();
        let vulns = vec![VulnerabilityView {
            bom_ref: "vuln-003".to_string(),
            id: "CVE-2024-3333".to_string(),
            affected_component: "pkg:pypi/urllib3@1.26.0".to_string(),
            affected_component_name: "urllib3".to_string(),
            affected_version: "1.26.0".to_string(),
            cvss_score: Some(2.5),
            cvss_vector: None,
            severity: SeverityView::Low,
            fixed_version: Some("1.27.0".to_string()),
            description: None,
            source_url: None,
        }];

        let mut output = String::new();
        formatter.render_informational_vulnerabilities(&mut output, &vulns);

        assert!(output.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(output.contains("CVE-2024-3333"));
        assert!(output.contains("🟢"));
        assert!(output.contains("2.5"));
        assert!(output.contains("1.27.0"));
    }

    #[test]
    fn test_render_actionable_vulnerabilities_multiple_packages() {
        let formatter = MarkdownFormatter::new();
        let vulns = vec![
            VulnerabilityView {
                bom_ref: "vuln-001".to_string(),
                id: "CVE-2024-1111".to_string(),
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
                id: "CVE-2024-4444".to_string(),
                affected_component: "pkg:pypi/urllib3@1.26.0".to_string(),
                affected_component_name: "urllib3".to_string(),
                affected_version: "1.26.0".to_string(),
                cvss_score: Some(8.0),
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: None,
                description: None,
                source_url: None,
            },
        ];

        let mut output = String::new();
        formatter.render_actionable_vulnerabilities(&mut output, &vulns);

        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 2 packages."));
    }

    #[test]
    fn test_count_unique_packages() {
        let vulns = vec![
            VulnerabilityView {
                bom_ref: "v1".to_string(),
                id: "CVE-1".to_string(),
                affected_component: "pkg:pypi/a@1.0".to_string(),
                affected_component_name: "a".to_string(),
                affected_version: "1.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::High,
                fixed_version: None,
                description: None,
                source_url: None,
            },
            VulnerabilityView {
                bom_ref: "v2".to_string(),
                id: "CVE-2".to_string(),
                affected_component: "pkg:pypi/a@1.0".to_string(),
                affected_component_name: "a".to_string(),
                affected_version: "1.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::Medium,
                fixed_version: None,
                description: None,
                source_url: None,
            },
            VulnerabilityView {
                bom_ref: "v3".to_string(),
                id: "CVE-3".to_string(),
                affected_component: "pkg:pypi/b@2.0".to_string(),
                affected_component_name: "b".to_string(),
                affected_version: "2.0".to_string(),
                cvss_score: None,
                cvss_vector: None,
                severity: SeverityView::Low,
                fixed_version: None,
                description: None,
                source_url: None,
            },
        ];

        assert_eq!(MarkdownFormatter::count_unique_packages(&vulns), 2);
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

        let formatter = MarkdownFormatter::new();
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
    // PyPI hyperlink tests
    // ============================================================

    #[test]
    fn test_normalize_for_pypi_underscore() {
        assert_eq!(
            MarkdownFormatter::normalize_for_pypi("typing_extensions"),
            "typing-extensions"
        );
    }

    #[test]
    fn test_normalize_for_pypi_uppercase() {
        assert_eq!(MarkdownFormatter::normalize_for_pypi("Flask"), "flask");
    }

    #[test]
    fn test_normalize_for_pypi_already_normalized() {
        assert_eq!(
            MarkdownFormatter::normalize_for_pypi("ruamel-yaml"),
            "ruamel-yaml"
        );
    }

    #[test]
    fn test_package_to_pypi_link_simple() {
        assert_eq!(
            MarkdownFormatter::package_to_pypi_link("requests"),
            "[requests](https://pypi.org/project/requests/)"
        );
    }

    #[test]
    fn test_package_to_pypi_link_with_underscore() {
        assert_eq!(
            MarkdownFormatter::package_to_pypi_link("typing_extensions"),
            "[typing_extensions](https://pypi.org/project/typing-extensions/)"
        );
    }

    #[test]
    fn test_package_to_pypi_link_with_uppercase() {
        assert_eq!(
            MarkdownFormatter::package_to_pypi_link("Flask"),
            "[Flask](https://pypi.org/project/flask/)"
        );
    }

    #[test]
    fn test_format_basic_contains_pypi_links() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new();

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

        let formatter = MarkdownFormatter::new();
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

        let formatter = MarkdownFormatter::new();
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

        let formatter = MarkdownFormatter::with_verified_packages(verified);
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
        let formatter = MarkdownFormatter::new();
        let markdown = formatter.format(&model).unwrap();

        // Without verification, all packages get hyperlinks
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
    }

    #[test]
    fn test_format_with_empty_verified_set_no_links() {
        let model = create_test_read_model();
        let verified = HashSet::new();

        let formatter = MarkdownFormatter::with_verified_packages(verified);
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
        let formatter = MarkdownFormatter::with_verified_packages(verified);
        let markdown = formatter.format(&model).unwrap();

        // Vulnerability table should show plain text for unverified package
        assert!(!markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("| requests |"));
    }

    #[test]
    fn test_format_package_name_with_none_verified() {
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_package_name("requests");
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    #[test]
    fn test_format_package_name_with_verified_present() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter = MarkdownFormatter::with_verified_packages(verified);
        let result = formatter.format_package_name("requests");
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    #[test]
    fn test_format_package_name_with_verified_absent() {
        let verified = HashSet::new();
        let formatter = MarkdownFormatter::with_verified_packages(verified);
        let result = formatter.format_package_name("nonexistent-pkg");
        assert_eq!(result, "nonexistent-pkg");
    }
}
