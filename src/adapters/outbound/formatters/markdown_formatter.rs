use crate::ports::outbound::{EnrichedPackage, SbomFormatter};
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};
use crate::shared::Result;
use std::collections::HashMap;

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
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomFormatter for MarkdownFormatter {
    fn format(&self, packages: Vec<EnrichedPackage>, _metadata: &SbomMetadata) -> Result<String> {
        let mut output = String::new();

        output.push_str("# Software Bill of Materials (SBOM)\n\n");
        output.push_str("## Component Inventory\n\n");
        output.push_str("A comprehensive list of all software components and libraries included in this project.\n\n");
        output.push_str("| Package | Version | License | Description |\n");
        output.push_str("|---------|---------|---------|-------------|\n");

        for enriched in &packages {
            output.push_str(&Self::format_package_row(enriched));
        }

        Ok(output)
    }

    fn format_with_dependencies(
        &self,
        dependency_graph: &DependencyGraph,
        packages: Vec<EnrichedPackage>,
        _metadata: &SbomMetadata,
    ) -> Result<String> {
        let mut output = String::new();
        let package_map = Self::create_package_map(&packages);

        // Header
        output.push_str("# Software Bill of Materials (SBOM)\n\n");

        // Component Inventory section (all packages)
        output.push_str("## Component Inventory\n\n");
        output.push_str("A comprehensive list of all software components and libraries included in this project.\n\n");
        output.push_str("| Package | Version | License | Description |\n");
        output.push_str("|---------|---------|---------|-------------|\n");

        for enriched in &packages {
            output.push_str(&Self::format_package_row(enriched));
        }
        output.push('\n');

        // Direct Dependencies section
        output.push_str("## Direct Dependencies\n\n");
        output.push_str("Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).\n\n");

        if dependency_graph.direct_dependency_count() > 0 {
            output.push_str("| Package | Version | License | Description |\n");
            output.push_str("|---------|---------|---------|-------------|\n");

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
                output.push_str("| Package | Version | License | Description |\n");
                output.push_str("|---------|---------|---------|-------------|\n");

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

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format(enriched, &metadata);

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
        let graph = DependencyGraph::new(vec![pkg1, pkg2, pkg3], direct_deps, transitive_deps);

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_with_dependencies(&graph, enriched, &metadata);

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
}
