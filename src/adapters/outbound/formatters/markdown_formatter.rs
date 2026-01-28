use crate::application::read_models::{
    ComponentView, DependencyView, SbomReadModel, VulnerabilityReportView, VulnerabilityView,
};
use crate::ports::outbound::{EnrichedPackage, SbomFormatter};
use crate::sbom_generation::domain::services::{
    VulnerabilityCheckResult, VulnerabilityChecker, VulnerabilityRow,
};
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};
use crate::shared::Result;
use std::collections::HashMap;

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
pub struct MarkdownFormatter;

impl MarkdownFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Escapes pipe characters and newlines for safe Markdown table rendering
    fn escape_markdown_table_cell(text: &str) -> String {
        text.replace('|', "\\|").replace('\n', " ")
    }

    /// Creates a package lookup map for quick access by name
    fn create_package_map(packages: &[EnrichedPackage]) -> HashMap<String, &EnrichedPackage> {
        packages
            .iter()
            .map(|p| (p.package.name().to_string(), p))
            .collect()
    }

    /// Formats a table row for a package
    fn format_package_row(enriched: &EnrichedPackage) -> String {
        let pkg = &enriched.package;
        let license = enriched.license.as_deref().unwrap_or("N/A");
        let description = enriched.description.as_deref().unwrap_or("");

        format!(
            "| {} | {} | {} | {} |\n",
            Self::escape_markdown_table_cell(pkg.name()),
            Self::escape_markdown_table_cell(pkg.version()),
            Self::escape_markdown_table_cell(license),
            Self::escape_markdown_table_cell(description)
        )
    }

    /// Formats vulnerability report section
    ///
    /// Returns markdown formatted vulnerability table with:
    /// - Package name and current version
    /// - Fixed version (if available)
    /// - CVSS score
    /// - Severity with emoji indicator
    /// - CVE identifier
    fn format_vulnerability_section(vulnerabilities: &[PackageVulnerabilities]) -> String {
        let mut output = String::new();
        output.push_str("\n## Vulnerability Report\n\n");
        output.push_str("**⚠️ Security Issues Detected**\n\n");

        // Calculate summary statistics
        let total_vulnerabilities: usize = vulnerabilities
            .iter()
            .map(|pv| pv.vulnerabilities().len())
            .sum();
        let package_count = vulnerabilities.len();

        output.push_str(&format!(
            "Found {} {} in {} {}.\n\n",
            total_vulnerabilities,
            if total_vulnerabilities == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            package_count,
            if package_count == 1 {
                "package"
            } else {
                "packages"
            }
        ));

        // Table header
        output.push_str(VULN_TABLE_HEADER);
        output.push_str(VULN_TABLE_SEPARATOR);

        // Table rows - one row per vulnerability
        for pkg_vuln in vulnerabilities {
            for vuln in pkg_vuln.vulnerabilities() {
                let cvss_display = vuln
                    .cvss_score()
                    .map_or("N/A".to_string(), |s| format!("{:.1}", s.value()));
                let fixed_version = vuln.fixed_version().unwrap_or("N/A");
                let severity = vuln.severity();

                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} {:?} | {} |\n",
                    Self::escape_markdown_table_cell(pkg_vuln.package_name()),
                    Self::escape_markdown_table_cell(pkg_vuln.current_version()),
                    Self::escape_markdown_table_cell(fixed_version),
                    cvss_display,
                    severity.emoji(),
                    severity,
                    Self::escape_markdown_table_cell(vuln.id()),
                ));
            }
        }

        // Attribution
        output.push_str("\n---\n\n");
        output
            .push_str("*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*\n");

        output
    }

    /// Formats message when no vulnerabilities are found
    fn format_no_vulnerabilities() -> String {
        let mut output = String::new();
        output.push_str("\n## Vulnerability Report\n\n");
        output.push_str("**✅ No Known Vulnerabilities**\n\n");
        output.push_str("No security vulnerabilities were found in the scanned packages.\n\n");
        output.push_str("---\n\n");
        output
            .push_str("*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*\n");
        output
    }

    /// Formats a single vulnerability row for markdown table output
    fn format_vulnerability_row(row: &VulnerabilityRow) -> String {
        format!(
            "| {} | {} | {} | {} | {} {:?} | {} |\n",
            Self::escape_markdown_table_cell(&row.package_name),
            Self::escape_markdown_table_cell(&row.current_version),
            Self::escape_markdown_table_cell(&row.fixed_version),
            row.cvss_display,
            row.severity.emoji(),
            row.severity,
            Self::escape_markdown_table_cell(&row.cve_id),
        )
    }

    /// Formats the Warning section for vulnerabilities above threshold
    fn format_vulnerability_warning_section(result: &VulnerabilityCheckResult) -> String {
        let mut output = String::new();

        let total_vulns = result.actionable_count();
        let package_count = result.actionable_package_count();

        output.push_str(&format!(
            "### ⚠️Warning Found {} {} in {} {}.\n\n",
            total_vulns,
            if total_vulns == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            package_count,
            if package_count == 1 {
                "package"
            } else {
                "packages"
            }
        ));

        // Table header
        output.push_str(VULN_TABLE_HEADER);
        output.push_str(VULN_TABLE_SEPARATOR);

        // Sort and format rows using domain service
        let sorted_rows = VulnerabilityChecker::sort_by_severity(&result.above_threshold);
        for row in &sorted_rows {
            output.push_str(&Self::format_vulnerability_row(row));
        }

        output
    }

    /// Formats the Info section for vulnerabilities below threshold
    fn format_vulnerability_info_section(result: &VulnerabilityCheckResult) -> String {
        let mut output = String::new();

        let total_vulns = result.informational_count();
        let package_count = result.informational_package_count();

        output.push_str(&format!(
            "### ℹ️Info Found {} {} in {} {}.\n\n",
            total_vulns,
            if total_vulns == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
            package_count,
            if package_count == 1 {
                "package"
            } else {
                "packages"
            }
        ));

        // Table header
        output.push_str(VULN_TABLE_HEADER);
        output.push_str(VULN_TABLE_SEPARATOR);

        // Sort and format rows using domain service
        let sorted_rows = VulnerabilityChecker::sort_by_severity(&result.below_threshold);
        for row in &sorted_rows {
            output.push_str(&Self::format_vulnerability_row(row));
        }

        output
    }

    /// Formats vulnerability report with Warning and Info sections based on threshold
    fn format_vulnerability_with_threshold(result: &VulnerabilityCheckResult) -> String {
        let mut output = String::new();
        output.push_str("\n## Vulnerability Report\n\n");

        // Warning section (above threshold)
        if !result.has_actionable_vulnerabilities() {
            output.push_str("### ⚠️Warning No vulnerabilities found above threshold.\n\n");
        } else {
            output.push_str(&Self::format_vulnerability_warning_section(result));
            output.push('\n');
        }

        // Info section (below threshold)
        if result.has_informational_vulnerabilities() {
            output.push_str(&Self::format_vulnerability_info_section(result));
        }

        // Attribution
        output.push_str("\n---\n\n");
        output
            .push_str("*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*\n");

        output
    }
}

/// format_v2 helper methods
#[allow(dead_code)]
impl MarkdownFormatter {
    /// Renders the header section for format_v2 output
    fn render_header_v2(&self, output: &mut String) {
        output.push_str("# Software Bill of Materials (SBOM)\n\n");
    }

    /// Renders the components section for format_v2 output
    fn render_components_v2(&self, output: &mut String, components: &[ComponentView]) {
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
                Self::escape_markdown_table_cell(&component.name),
                Self::escape_markdown_table_cell(&component.version),
                Self::escape_markdown_table_cell(license),
                Self::escape_markdown_table_cell(description)
            ));
        }
        output.push('\n');
    }

    /// Renders the dependencies section for format_v2 output
    fn render_dependencies_v2(
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
                        Self::escape_markdown_table_cell(&component.name),
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
                                Self::escape_markdown_table_cell(&component.name),
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

    /// Renders the vulnerabilities section for format_v2 output
    fn render_vulnerabilities_v2(&self, output: &mut String, vulns: &VulnerabilityReportView) {
        output.push_str("\n## Vulnerability Report\n\n");

        // Warning section (actionable vulnerabilities)
        if vulns.actionable.is_empty() {
            output.push_str("### ⚠️Warning No vulnerabilities found above threshold.\n\n");
        } else {
            let total_vulns = vulns.actionable.len();
            let package_count = vulns.summary.affected_package_count.max(1);

            output.push_str(&format!(
                "### ⚠️Warning Found {} {} in {} {}.\n\n",
                total_vulns,
                if total_vulns == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                },
                package_count,
                if package_count == 1 {
                    "package"
                } else {
                    "packages"
                }
            ));

            output.push_str(VULN_TABLE_HEADER);
            output.push_str(VULN_TABLE_SEPARATOR);

            // Sort by severity (Critical first)
            let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.actionable.iter().collect();
            sorted_vulns.sort_by(|a, b| a.severity.cmp(&b.severity));

            for vuln in sorted_vulns {
                self.render_vulnerability_row_v2(output, vuln);
            }
            output.push('\n');
        }

        // Info section (informational vulnerabilities)
        if !vulns.informational.is_empty() {
            let total_vulns = vulns.informational.len();
            let package_count = vulns.summary.affected_package_count.max(1);

            output.push_str(&format!(
                "### ℹ️Info Found {} {} in {} {}.\n\n",
                total_vulns,
                if total_vulns == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                },
                package_count,
                if package_count == 1 {
                    "package"
                } else {
                    "packages"
                }
            ));

            output.push_str(VULN_TABLE_HEADER);
            output.push_str(VULN_TABLE_SEPARATOR);

            let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.informational.iter().collect();
            sorted_vulns.sort_by(|a, b| a.severity.cmp(&b.severity));

            for vuln in sorted_vulns {
                self.render_vulnerability_row_v2(output, vuln);
            }
        }

        // Attribution
        output.push_str("\n---\n\n");
        output
            .push_str("*Vulnerability data provided by [OSV](https://osv.dev) under CC-BY 4.0*\n");
    }

    /// Renders a single vulnerability row for format_v2 output
    fn render_vulnerability_row_v2(&self, output: &mut String, vuln: &VulnerabilityView) {
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
            Self::escape_markdown_table_cell(&vuln.affected_component_name),
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
    fn format(
        &self,
        packages: Vec<EnrichedPackage>,
        _metadata: &SbomMetadata,
        vulnerability_report: Option<&[PackageVulnerabilities]>,
    ) -> Result<String> {
        let mut output = String::new();

        output.push_str("# Software Bill of Materials (SBOM)\n\n");
        output.push_str("## Component Inventory\n\n");
        output.push_str("A comprehensive list of all software components and libraries included in this project.\n\n");
        output.push_str(TABLE_HEADER);
        output.push_str(TABLE_SEPARATOR);

        for enriched in &packages {
            output.push_str(&Self::format_package_row(enriched));
        }

        // Add vulnerability section if present
        if let Some(vulnerabilities) = vulnerability_report {
            if vulnerabilities.is_empty() {
                output.push_str(&Self::format_no_vulnerabilities());
            } else {
                output.push_str(&Self::format_vulnerability_section(vulnerabilities));
            }
        }

        Ok(output)
    }

    fn format_with_dependencies(
        &self,
        dependency_graph: &DependencyGraph,
        packages: Vec<EnrichedPackage>,
        _metadata: &SbomMetadata,
        vulnerability_report: Option<&[PackageVulnerabilities]>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
    ) -> Result<String> {
        let mut output = String::new();
        let package_map = Self::create_package_map(&packages);

        // Header
        output.push_str("# Software Bill of Materials (SBOM)\n\n");

        // Component Inventory section (all packages)
        output.push_str("## Component Inventory\n\n");
        output.push_str("A comprehensive list of all software components and libraries included in this project.\n\n");
        output.push_str(TABLE_HEADER);
        output.push_str(TABLE_SEPARATOR);

        for enriched in &packages {
            output.push_str(&Self::format_package_row(enriched));
        }
        output.push('\n');

        // Direct Dependencies section
        output.push_str("## Direct Dependencies\n\n");
        output.push_str("Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).\n\n");

        if dependency_graph.direct_dependency_count() > 0 {
            output.push_str(TABLE_HEADER);
            output.push_str(TABLE_SEPARATOR);

            for dep in dependency_graph.direct_dependencies() {
                if let Some(enriched) = package_map.get(dep.as_str()) {
                    output.push_str(&Self::format_package_row(enriched));
                }
            }
            output.push('\n');
        } else {
            output.push_str("*No direct dependencies*\n\n");
        }

        // Transitive Dependencies section
        output.push_str("## Transitive Dependencies\n\n");
        output.push_str("Secondary dependencies introduced by the primary packages.\n\n");

        if dependency_graph.transitive_dependency_count() > 0 {
            for (direct_dep, trans_deps) in dependency_graph.transitive_dependencies() {
                output.push_str(&format!("### Dependencies for {}\n\n", direct_dep.as_str()));
                output.push_str(TABLE_HEADER);
                output.push_str(TABLE_SEPARATOR);

                for trans_dep in trans_deps {
                    if let Some(enriched) = package_map.get(trans_dep.as_str()) {
                        output.push_str(&Self::format_package_row(enriched));
                    }
                }
                output.push('\n');
            }
        } else {
            output.push_str("*No transitive dependencies*\n\n");
        }

        // Add vulnerability section
        // Priority: use VulnerabilityCheckResult if available, otherwise fall back to vulnerability_report
        if let Some(result) = vulnerability_result {
            if !result.has_actionable_vulnerabilities()
                && !result.has_informational_vulnerabilities()
            {
                output.push_str(&Self::format_no_vulnerabilities());
            } else {
                output.push_str(&Self::format_vulnerability_with_threshold(result));
            }
        } else if let Some(vulnerabilities) = vulnerability_report {
            if vulnerabilities.is_empty() {
                output.push_str(&Self::format_no_vulnerabilities());
            } else {
                output.push_str(&Self::format_vulnerability_section(vulnerabilities));
            }
        }

        Ok(output)
    }

    fn format_v2(&self, model: &SbomReadModel) -> Result<String> {
        let mut output = String::new();

        // Header section
        self.render_header_v2(&mut output);

        // Components section
        self.render_components_v2(&mut output, &model.components);

        // Dependencies section (if present)
        if let Some(deps) = &model.dependencies {
            self.render_dependencies_v2(&mut output, deps, &model.components);
        }

        // Vulnerabilities section (if present)
        if let Some(vulns) = &model.vulnerabilities {
            self.render_vulnerabilities_v2(&mut output, vulns);
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
    use crate::sbom_generation::domain::{Package, PackageName};
    use crate::sbom_generation::services::SbomGenerator;
    use std::collections::HashMap;

    #[test]
    fn test_markdown_formatter_basic() {
        let pkg = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let enriched = vec![EnrichedPackage::new(
            pkg,
            Some("Apache 2.0".to_string()),
            Some("HTTP library".to_string()),
        )];

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format(enriched, &metadata, None);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("# Software Bill of Materials (SBOM)"));
        assert!(markdown.contains("## Component Inventory"));
        assert!(markdown.contains("requests"));
        assert!(markdown.contains("Apache 2.0"));
    }

    #[test]
    fn test_markdown_formatter_with_dependencies() {
        let pkg1 = Package::new("myproject".to_string(), "1.0.0".to_string()).unwrap();
        let pkg2 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let pkg3 = Package::new("urllib3".to_string(), "1.26.0".to_string()).unwrap();

        let enriched = vec![
            EnrichedPackage::new(pkg1.clone(), None, None),
            EnrichedPackage::new(
                pkg2.clone(),
                Some("Apache 2.0".to_string()),
                Some("HTTP library".to_string()),
            ),
            EnrichedPackage::new(pkg3.clone(), Some("MIT".to_string()), None),
        ];

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let mut transitive_deps = HashMap::new();
        transitive_deps.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![PackageName::new("urllib3".to_string()).unwrap()],
        );
        let graph = DependencyGraph::new(direct_deps, transitive_deps);

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_with_dependencies(&graph, enriched, &metadata, None, None);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Component Inventory"));
        assert!(markdown.contains("## Direct Dependencies"));
        assert!(markdown.contains("## Transitive Dependencies"));
        assert!(markdown.contains("### Dependencies for requests"));
        assert!(markdown.contains("requests"));
        assert!(markdown.contains("urllib3"));
    }

    #[test]
    fn test_escape_markdown_table_cell() {
        let input = "Text with | pipe and\nnewline";
        let escaped = MarkdownFormatter::escape_markdown_table_cell(input);
        assert_eq!(escaped, "Text with \\| pipe and newline");
    }

    #[test]
    fn test_markdown_formatter_with_vulnerabilities() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        let pkg = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let enriched = vec![EnrichedPackage::new(
            pkg,
            Some("Apache 2.0".to_string()),
            Some("HTTP library".to_string()),
        )];

        // Create vulnerability data
        let vuln1 = Vulnerability::new(
            "CVE-2024-1234".to_string(),
            Some(CvssScore::new(9.8).unwrap()),
            Severity::Critical,
            Some("2.32.0".to_string()),
            Some("Security issue".to_string()),
        )
        .unwrap();

        let vuln2 = Vulnerability::new(
            "CVE-2024-5678".to_string(),
            Some(CvssScore::new(5.3).unwrap()),
            Severity::Medium,
            Some("2.32.1".to_string()),
            None,
        )
        .unwrap();

        let pkg_vulns = PackageVulnerabilities::new(
            "requests".to_string(),
            "2.31.0".to_string(),
            vec![vuln1, vuln2],
        );

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format(enriched, &metadata, Some(&[pkg_vulns]));

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Vulnerability Report"));
        assert!(markdown.contains("⚠️ Security Issues Detected"));
        assert!(markdown.contains("CVE-2024-1234"));
        assert!(markdown.contains("CVE-2024-5678"));
        assert!(markdown.contains("9.8"));
        assert!(markdown.contains("5.3"));
        assert!(markdown.contains("🔴"));
        assert!(markdown.contains("🟡"));
        assert!(markdown.contains("2.32.0"));
        assert!(markdown.contains("2.32.1"));
        assert!(markdown.contains("OSV"));
        assert!(markdown.contains("CC-BY 4.0"));
    }

    #[test]
    fn test_markdown_formatter_with_empty_vulnerabilities() {
        let pkg = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let enriched = vec![EnrichedPackage::new(
            pkg,
            Some("Apache 2.0".to_string()),
            Some("HTTP library".to_string()),
        )];

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format(enriched, &metadata, Some(&[]));

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Vulnerability Report"));
        assert!(markdown.contains("✅ No Known Vulnerabilities"));
        assert!(markdown.contains("No security vulnerabilities were found"));
        assert!(markdown.contains("OSV"));
        assert!(markdown.contains("CC-BY 4.0"));
    }

    #[test]
    fn test_markdown_formatter_without_vulnerability_check() {
        let pkg = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let enriched = vec![EnrichedPackage::new(
            pkg,
            Some("Apache 2.0".to_string()),
            Some("HTTP library".to_string()),
        )];

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format(enriched, &metadata, None);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(!markdown.contains("## Vulnerability Report"));
        assert!(!markdown.contains("OSV"));
    }

    #[test]
    fn test_markdown_formatter_with_dependencies_and_vulnerabilities() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        let pkg1 = Package::new("myproject".to_string(), "1.0.0".to_string()).unwrap();
        let pkg2 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let pkg3 = Package::new("urllib3".to_string(), "1.26.0".to_string()).unwrap();

        let enriched = vec![
            EnrichedPackage::new(pkg1.clone(), None, None),
            EnrichedPackage::new(
                pkg2.clone(),
                Some("Apache 2.0".to_string()),
                Some("HTTP library".to_string()),
            ),
            EnrichedPackage::new(pkg3.clone(), Some("MIT".to_string()), None),
        ];

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let mut transitive_deps = HashMap::new();
        transitive_deps.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![PackageName::new("urllib3".to_string()).unwrap()],
        );
        let graph = DependencyGraph::new(direct_deps, transitive_deps);

        // Create vulnerability data
        let vuln = Vulnerability::new(
            "CVE-2024-1234".to_string(),
            Some(CvssScore::new(7.5).unwrap()),
            Severity::High,
            Some("1.27.0".to_string()),
            None,
        )
        .unwrap();

        let pkg_vulns =
            PackageVulnerabilities::new("urllib3".to_string(), "1.26.0".to_string(), vec![vuln]);

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_with_dependencies(
            &graph,
            enriched,
            &metadata,
            Some(&[pkg_vulns]),
            None,
        );

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Component Inventory"));
        assert!(markdown.contains("## Direct Dependencies"));
        assert!(markdown.contains("## Transitive Dependencies"));
        assert!(markdown.contains("## Vulnerability Report"));
        assert!(markdown.contains("CVE-2024-1234"));
        assert!(markdown.contains("urllib3"));
        assert!(markdown.contains("7.5"));
        assert!(markdown.contains("🟠"));
    }

    #[test]
    fn test_vulnerability_formatting_with_missing_cvss() {
        use crate::sbom_generation::domain::vulnerability::{
            PackageVulnerabilities, Severity, Vulnerability,
        };

        let vuln = Vulnerability::new(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            None,
            Severity::High,
            None,
            None,
        )
        .unwrap();

        let pkg_vulns =
            PackageVulnerabilities::new("test-pkg".to_string(), "1.0.0".to_string(), vec![vuln]);

        let output = MarkdownFormatter::format_vulnerability_section(&[pkg_vulns]);

        assert!(output.contains("N/A")); // CVSS should be N/A
        assert!(output.contains("GHSA-xxxx-yyyy-zzzz"));
    }

    #[test]
    fn test_vulnerability_warning_section() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        let vuln1 = Vulnerability::new(
            "CVE-2024-001".to_string(),
            Some(CvssScore::new(9.8).unwrap()),
            Severity::Critical,
            Some("2.0.0".to_string()),
            None,
        )
        .unwrap();

        let vuln2 = Vulnerability::new(
            "CVE-2024-002".to_string(),
            Some(CvssScore::new(7.5).unwrap()),
            Severity::High,
            Some("2.1.0".to_string()),
            None,
        )
        .unwrap();

        let pkg_vulns = PackageVulnerabilities::new(
            "requests".to_string(),
            "2.25.0".to_string(),
            vec![vuln1, vuln2],
        );

        let result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vulns],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let output = MarkdownFormatter::format_vulnerability_warning_section(&result);

        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 1 package."));
        assert!(output.contains("CVE-2024-001"));
        assert!(output.contains("CVE-2024-002"));
        assert!(output.contains("🔴"));
        assert!(output.contains("🟠"));
    }

    #[test]
    fn test_vulnerability_info_section() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        let vuln1 = Vulnerability::new(
            "CVE-2024-003".to_string(),
            Some(CvssScore::new(3.1).unwrap()),
            Severity::Low,
            Some("6.0".to_string()),
            None,
        )
        .unwrap();

        let vuln2 =
            Vulnerability::new("CVE-2024-004".to_string(), None, Severity::None, None, None)
                .unwrap();

        let pkg_vulns = PackageVulnerabilities::new(
            "pyyaml".to_string(),
            "5.4".to_string(),
            vec![vuln1, vuln2],
        );

        let result = VulnerabilityCheckResult {
            above_threshold: vec![],
            below_threshold: vec![pkg_vulns],
            threshold_exceeded: false,
        };

        let output = MarkdownFormatter::format_vulnerability_info_section(&result);

        assert!(output.contains("### ℹ️Info Found 2 vulnerabilities in 1 package."));
        assert!(output.contains("CVE-2024-003"));
        assert!(output.contains("CVE-2024-004"));
        assert!(output.contains("🟢"));
        assert!(output.contains("⚪"));
    }

    #[test]
    fn test_vulnerability_with_threshold_result() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        // Above threshold vulnerabilities
        let vuln_critical = Vulnerability::new(
            "CVE-2024-001".to_string(),
            Some(CvssScore::new(9.8).unwrap()),
            Severity::Critical,
            Some("2.0.0".to_string()),
            None,
        )
        .unwrap();

        let vuln_high = Vulnerability::new(
            "CVE-2024-002".to_string(),
            Some(CvssScore::new(7.5).unwrap()),
            Severity::High,
            Some("2.1.0".to_string()),
            None,
        )
        .unwrap();

        let above_pkg = PackageVulnerabilities::new(
            "requests".to_string(),
            "2.25.0".to_string(),
            vec![vuln_critical, vuln_high],
        );

        // Below threshold vulnerabilities
        let vuln_low = Vulnerability::new(
            "CVE-2024-003".to_string(),
            Some(CvssScore::new(3.1).unwrap()),
            Severity::Low,
            Some("6.0".to_string()),
            None,
        )
        .unwrap();

        let below_pkg =
            PackageVulnerabilities::new("pyyaml".to_string(), "5.4".to_string(), vec![vuln_low]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![above_pkg],
            below_threshold: vec![below_pkg],
            threshold_exceeded: true,
        };

        let output = MarkdownFormatter::format_vulnerability_with_threshold(&result);

        // Check Warning section
        assert!(output.contains("## Vulnerability Report"));
        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 1 package."));
        assert!(output.contains("CVE-2024-001"));
        assert!(output.contains("CVE-2024-002"));

        // Check Info section
        assert!(output.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(output.contains("CVE-2024-003"));

        // Check attribution
        assert!(output.contains("OSV"));
        assert!(output.contains("CC-BY 4.0"));
    }

    #[test]
    fn test_vulnerability_with_threshold_empty_warning() {
        let result = VulnerabilityCheckResult {
            above_threshold: vec![],
            below_threshold: vec![],
            threshold_exceeded: false,
        };

        let output = MarkdownFormatter::format_vulnerability_with_threshold(&result);

        assert!(output.contains("### ⚠️Warning No vulnerabilities found above threshold."));
    }

    #[test]
    fn test_format_with_dependencies_uses_vulnerability_result() {
        use crate::sbom_generation::domain::vulnerability::{
            CvssScore, PackageVulnerabilities, Severity, Vulnerability,
        };

        let pkg = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();
        let enriched = vec![EnrichedPackage::new(pkg, None, None)];

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let graph = DependencyGraph::new(direct_deps, HashMap::new());

        let vuln = Vulnerability::new(
            "CVE-2024-1234".to_string(),
            Some(CvssScore::new(9.0).unwrap()),
            Severity::Critical,
            Some("3.0.0".to_string()),
            None,
        )
        .unwrap();

        let above_pkg =
            PackageVulnerabilities::new("requests".to_string(), "2.31.0".to_string(), vec![vuln]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![above_pkg],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let output = formatter
            .format_with_dependencies(&graph, enriched, &metadata, None, Some(&result))
            .unwrap();

        // Should use VulnerabilityCheckResult format (Warning section)
        assert!(output.contains("### ⚠️Warning Found 1 vulnerability in 1 package."));
        assert!(output.contains("CVE-2024-1234"));
    }

    // ============================================================
    // format_v2 tests
    // ============================================================

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
    fn test_format_v2_basic() {
        let model = create_test_read_model();
        let formatter = MarkdownFormatter::new();

        let result = formatter.format_v2(&model);

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
    fn test_format_v2_with_dependencies() {
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
        let result = formatter.format_v2(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Direct Dependencies"));
        assert!(markdown.contains("## Transitive Dependencies"));
        assert!(markdown.contains("### Dependencies for requests"));
        assert!(markdown.contains("urllib3"));
    }

    #[test]
    fn test_format_v2_with_vulnerabilities() {
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
        let result = formatter.format_v2(&model);

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
    fn test_format_v2_with_informational_vulnerabilities() {
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
        let result = formatter.format_v2(&model);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("### ⚠️Warning No vulnerabilities found above threshold."));
        assert!(markdown.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(markdown.contains("CVE-2024-5678"));
        assert!(markdown.contains("🟢"));
        assert!(markdown.contains("LOW"));
    }

    #[test]
    fn test_format_v2_output_matches_format_with_dependencies() {
        // Test that format_v2 produces similar output structure to format_with_dependencies
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
        let result = formatter.format_v2(&model);

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
}
