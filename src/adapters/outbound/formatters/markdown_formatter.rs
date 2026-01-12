use crate::ports::outbound::{EnrichedPackage, SbomFormatter};
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};
use crate::shared::Result;
use std::collections::HashMap;

/// Markdown table header for package information
const TABLE_HEADER: &str = "| Package | Version | License | Description |\n";

/// Markdown table separator line
const TABLE_SEPARATOR: &str = "|---------|---------|---------|-------------|\n";

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
        output
            .push_str("| Package | Current Version | Fixed Version | CVSS | Severity | CVE ID |\n");
        output
            .push_str("|---------|----------------|---------------|------|----------|--------|\n");

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
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_with_dependencies(&graph, enriched, &metadata, None);

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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0", false);
        let formatter = MarkdownFormatter::new();
        let result =
            formatter.format_with_dependencies(&graph, enriched, &metadata, Some(&[pkg_vulns]));

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
}
