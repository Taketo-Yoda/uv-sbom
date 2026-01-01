use crate::ports::outbound::{EnrichedPackage, SbomFormatter};
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};
use crate::shared::Result;

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
}

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomFormatter for MarkdownFormatter {
    fn format(&self, packages: Vec<EnrichedPackage>, metadata: &SbomMetadata) -> Result<String> {
        // Basic markdown output without dependency information
        let mut output = String::new();

        output.push_str("# Software Bill of Materials (SBOM)\n\n");
        output.push_str(&format!("**Generated**: {}\n", metadata.timestamp()));
        output.push_str(&format!(
            "**Tool**: {} {}\n\n",
            metadata.tool_name(),
            metadata.tool_version()
        ));

        output.push_str("## Packages\n\n");
        output.push_str("| Package | Version | License | Description |\n");
        output.push_str("|---------|---------|---------|-------------|\n");

        for enriched in packages {
            let pkg = &enriched.package;
            let license = enriched
                .license
                .as_deref()
                .unwrap_or("N/A");
            let description = enriched
                .description
                .as_deref()
                .unwrap_or("");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                Self::escape_markdown_table_cell(pkg.name()),
                Self::escape_markdown_table_cell(pkg.version()),
                Self::escape_markdown_table_cell(license),
                Self::escape_markdown_table_cell(description)
            ));
        }

        Ok(output)
    }

    fn format_with_dependencies(
        &self,
        dependency_graph: &DependencyGraph,
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
    ) -> Result<String> {
        let mut output = String::new();

        output.push_str("# Software Bill of Materials (SBOM)\n\n");
        output.push_str(&format!("**Generated**: {}\n", metadata.timestamp()));
        output.push_str(&format!(
            "**Tool**: {} {}\n\n",
            metadata.tool_name(),
            metadata.tool_version()
        ));

        // Summary section
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- **Total Packages**: {}\n",
            dependency_graph.total_package_count()
        ));
        output.push_str(&format!(
            "- **Direct Dependencies**: {}\n",
            dependency_graph.direct_dependency_count()
        ));
        output.push_str(&format!(
            "- **Transitive Dependencies**: {}\n\n",
            dependency_graph.transitive_dependency_count()
        ));

        // Direct dependencies section
        output.push_str("## Direct Dependencies\n\n");
        if dependency_graph.direct_dependency_count() > 0 {
            for dep in dependency_graph.direct_dependencies() {
                output.push_str(&format!("- `{}`\n", dep.as_str()));
            }
            output.push('\n');
        } else {
            output.push_str("*No direct dependencies*\n\n");
        }

        // Transitive dependencies section
        output.push_str("## Transitive Dependencies\n\n");
        if dependency_graph.transitive_dependency_count() > 0 {
            for (direct_dep, trans_deps) in dependency_graph.transitive_dependencies() {
                output.push_str(&format!("### Dependencies of `{}`\n\n", direct_dep.as_str()));
                for trans_dep in trans_deps {
                    output.push_str(&format!("- `{}`\n", trans_dep.as_str()));
                }
                output.push('\n');
            }
        } else {
            output.push_str("*No transitive dependencies*\n\n");
        }

        // Full package list with details
        output.push_str("## Package Details\n\n");
        output.push_str("| Package | Version | License | Description |\n");
        output.push_str("|---------|---------|---------|-------------|\n");

        for enriched in packages {
            let pkg = &enriched.package;
            let license = enriched
                .license
                .as_deref()
                .unwrap_or("N/A");
            let description = enriched
                .description
                .as_deref()
                .unwrap_or("");

            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                Self::escape_markdown_table_cell(pkg.name()),
                Self::escape_markdown_table_cell(pkg.version()),
                Self::escape_markdown_table_cell(license),
                Self::escape_markdown_table_cell(description)
            ));
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
        assert!(markdown.contains("requests"));
        assert!(markdown.contains("Apache 2.0"));
    }

    #[test]
    fn test_markdown_formatter_with_dependencies() {
        let pkg1 = Package::new("myproject".to_string(), "1.0.0".to_string()).unwrap();
        let pkg2 = Package::new("requests".to_string(), "2.31.0".to_string()).unwrap();

        let enriched = vec![
            EnrichedPackage::new(pkg1.clone(), None, None),
            EnrichedPackage::new(pkg2.clone(), Some("Apache 2.0".to_string()), None),
        ];

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let graph = DependencyGraph::new(vec![pkg1, pkg2], direct_deps, HashMap::new());

        let metadata = SbomGenerator::generate_metadata("test-tool", "1.0.0");
        let formatter = MarkdownFormatter::new();
        let result = formatter.format_with_dependencies(&graph, enriched, &metadata);

        assert!(result.is_ok());
        let markdown = result.unwrap();
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("## Direct Dependencies"));
        assert!(markdown.contains("requests"));
    }

    #[test]
    fn test_escape_markdown_table_cell() {
        let input = "Text with | pipe and\nnewline";
        let escaped = MarkdownFormatter::escape_markdown_table_cell(input);
        assert_eq!(escaped, "Text with \\| pipe and newline");
    }
}
