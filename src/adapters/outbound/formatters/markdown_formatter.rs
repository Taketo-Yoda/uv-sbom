use crate::application::read_models::{
    ComponentView, DependencyView, IntroducedByView, LicenseComplianceView, ResolutionGuideView,
    SbomReadModel, UpgradeEntryView, UpgradeRecommendationView, VulnerabilityReportView,
    VulnerabilitySummary, VulnerabilityView,
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

    /// Generate a Markdown hyperlink for a vulnerability ID based on its prefix.
    ///
    /// - `CVE-*` → NVD (NIST)
    /// - `GHSA-*` → GitHub Advisories
    /// - All others (PYSEC, RUSTSEC, etc.) → OSV.dev
    fn vulnerability_id_to_link(id: &str) -> String {
        let url = if id.starts_with("CVE-") {
            format!("https://nvd.nist.gov/vuln/detail/{}", id)
        } else if id.starts_with("GHSA-") {
            format!("https://github.com/advisories/{}", id)
        } else {
            format!("https://osv.dev/vulnerability/{}", id)
        };
        format!("[{}]({})", Self::escape_markdown_table_cell(id), url)
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

    /// Generates a Markdown table separator row from column header strings.
    /// Each separator cell width matches the header's char count plus two spaces.
    fn make_separator(cols: &[&str]) -> String {
        let mut sep = String::from("|");
        for col in cols {
            let dashes = "-".repeat(col.chars().count() + 2);
            sep.push_str(&dashes);
            sep.push('|');
        }
        sep.push('\n');
        sep
    }

    /// Locale-aware package table header line
    fn table_header(&self) -> String {
        format!(
            "| {} | {} | {} | {} |\n",
            self.messages.col_package,
            self.messages.col_version,
            self.messages.col_license,
            self.messages.col_description,
        )
    }

    /// Locale-aware package table separator line
    fn table_separator(&self) -> String {
        Self::make_separator(&[
            self.messages.col_package,
            self.messages.col_version,
            self.messages.col_license,
            self.messages.col_description,
        ])
    }

    /// Locale-aware vulnerability table header line
    fn vuln_table_header(&self) -> String {
        format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            self.messages.col_package,
            self.messages.col_current_version,
            self.messages.col_fixed_version,
            self.messages.col_cvss,
            self.messages.col_severity,
            self.messages.col_vuln_id,
        )
    }

    /// Locale-aware vulnerability table separator line
    fn vuln_table_separator(&self) -> String {
        Self::make_separator(&[
            self.messages.col_package,
            self.messages.col_current_version,
            self.messages.col_fixed_version,
            self.messages.col_cvss,
            self.messages.col_severity,
            self.messages.col_vuln_id,
        ])
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
        output.push_str(
            "A comprehensive list of all software components and libraries included in this project.\n\n",
        );
        output.push_str(&self.table_header());
        output.push_str(&self.table_separator());

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
        output.push_str(self.messages.section_direct_deps);
        output.push_str("\n\n");
        output.push_str(
            "Primary packages explicitly defined in the project configuration(e.g., pyproject.toml).\n\n",
        );

        if !deps.direct.is_empty() {
            output.push_str(&self.table_header());
            output.push_str(&self.table_separator());

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
        output.push_str(self.messages.section_transitive_deps);
        output.push_str("\n\n");
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
                    output.push_str(&self.table_header());
                    output.push_str(&self.table_separator());

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
        output.push('\n');
        output.push_str(self.messages.section_vuln_report);
        output.push_str("\n\n");

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

        output.push_str(&self.vuln_table_header());
        output.push_str(&self.vuln_table_separator());

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

        output.push_str(&self.vuln_table_header());
        output.push_str(&self.vuln_table_separator());

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
            output.push_str("**No license violations found.**\n\n");
        }

        // Violations table
        if !compliance.violations.is_empty() {
            output.push_str("### Violations\n\n");
            output.push_str(&format!(
                "| {} | {} | {} | Reason | Matched Pattern |\n",
                self.messages.col_package, self.messages.col_version, self.messages.col_license,
            ));
            output.push_str(&Self::make_separator(&[
                self.messages.col_package,
                self.messages.col_version,
                self.messages.col_license,
                "Reason",
                "Matched Pattern",
            ]));

            for v in &compliance.violations {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    Self::escape_markdown_table_cell(&v.package_name),
                    Self::escape_markdown_table_cell(&v.package_version),
                    Self::escape_markdown_table_cell(&v.license),
                    Self::escape_markdown_table_cell(&v.reason),
                    v.matched_pattern.as_deref().unwrap_or("-"),
                ));
            }
            output.push('\n');
        }

        // Warnings table
        if !compliance.warnings.is_empty() {
            output.push_str(&format!(
                "### Warnings\n\n**{} {} with unknown license.**\n\n",
                compliance.summary.warning_count,
                if compliance.summary.warning_count == 1 {
                    "package"
                } else {
                    "packages"
                }
            ));
            output.push_str(&format!(
                "| {} | {} |\n",
                self.messages.col_package, self.messages.col_version,
            ));
            output.push_str(&Self::make_separator(&[
                self.messages.col_package,
                self.messages.col_version,
            ]));

            for w in &compliance.warnings {
                output.push_str(&format!(
                    "| {} | {} |\n",
                    Self::escape_markdown_table_cell(&w.package_name),
                    Self::escape_markdown_table_cell(&w.package_version),
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
        output.push_str("The following transitive dependencies have known vulnerabilities. ");
        output.push_str(
            "The table shows which direct dependency introduces each vulnerable package.\n\n",
        );

        if upgrade_recommendations.is_some() {
            output.push_str("| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Recommended Action | Vulnerability ID |\n");
            output.push_str("|--------------------|---------|--------------|---------|--------------------------|--------------------|------------------|\n");
        } else {
            output.push_str("| Vulnerable Package | Current | Fixed Version | Severity | Introduced By (Direct Dep) | Vulnerability ID |\n");
            output.push_str("|--------------------|---------|--------------|---------|--------------------------|-----------------|\n");
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
                let action = Self::find_upgrade_action(
                    recommendations,
                    &entry.vulnerability_id,
                    &entry.introduced_by,
                );
                output.push_str(&format!(
                    "| {} | {} | {} | {} {} | {} | {} | {} |\n",
                    Self::escape_markdown_table_cell(&entry.vulnerable_package),
                    Self::escape_markdown_table_cell(&entry.current_version),
                    Self::escape_markdown_table_cell(fixed),
                    severity_emoji,
                    entry.severity.as_str(),
                    Self::escape_markdown_table_cell(&introduced_by),
                    Self::escape_markdown_table_cell(&action),
                    Self::vulnerability_id_to_link(&entry.vulnerability_id),
                ));
            } else {
                output.push_str(&format!(
                    "| {} | {} | {} | {} {} | {} | {} |\n",
                    Self::escape_markdown_table_cell(&entry.vulnerable_package),
                    Self::escape_markdown_table_cell(&entry.current_version),
                    Self::escape_markdown_table_cell(fixed),
                    severity_emoji,
                    entry.severity.as_str(),
                    Self::escape_markdown_table_cell(&introduced_by),
                    Self::vulnerability_id_to_link(&entry.vulnerability_id),
                ));
            }
        }
        output.push('\n');
    }

    /// Finds the recommended action text for a resolution entry from upgrade recommendations.
    ///
    /// Matches by `vulnerability_id` for `Upgradable`/`Unresolvable` variants, and falls back
    /// to matching by direct dependency name for `SimulationFailed`.
    fn find_upgrade_action(
        recommendations: &UpgradeRecommendationView,
        vulnerability_id: &str,
        introduced_by: &[IntroducedByView],
    ) -> String {
        for rec in &recommendations.entries {
            match rec {
                UpgradeEntryView::Upgradable {
                    direct_dep,
                    target_version,
                    transitive_dep,
                    resolved_version,
                    vulnerability_id: vid,
                    ..
                } if vid == vulnerability_id => {
                    return format!(
                        "⬆️ Upgrade {} → {} (resolves {} to {})",
                        direct_dep, target_version, transitive_dep, resolved_version
                    );
                }
                UpgradeEntryView::Unresolvable {
                    reason,
                    vulnerability_id: vid,
                    ..
                } if vid == vulnerability_id => {
                    return format!("⚠️ Cannot resolve: {}", reason);
                }
                _ => {}
            }
        }

        let introduced_names: Vec<&str> = introduced_by
            .iter()
            .map(|ib| ib.package_name.as_str())
            .collect();
        for rec in &recommendations.entries {
            if let UpgradeEntryView::SimulationFailed { direct_dep, error } = rec {
                if introduced_names.contains(&direct_dep.as_str()) {
                    return format!("❓ Could not analyze: {}", error);
                }
            }
        }

        String::new()
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
            Self::vulnerability_id_to_link(&vuln.id),
        ));
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
        LicenseView, SbomMetadataView, SeverityView, VulnerabilitySummary,
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
    fn test_escape_markdown_table_cell() {
        let input = "Text with | pipe and\nnewline";
        let escaped = MarkdownFormatter::escape_markdown_table_cell(input);
        assert_eq!(escaped, "Text with \\| pipe and newline");
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

    // ============================================================
    // Vulnerability rendering unit tests
    // ============================================================

    #[test]
    fn test_render_vulnerability_summary() {
        let formatter = MarkdownFormatter::new(Locale::En);
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
        let formatter = MarkdownFormatter::new(Locale::En);
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
        let formatter = MarkdownFormatter::new(Locale::En);
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
        assert!(output.contains("[CVE-2024-1111](https://nvd.nist.gov/vuln/detail/CVE-2024-1111)"));
        assert!(output.contains("[CVE-2024-2222](https://nvd.nist.gov/vuln/detail/CVE-2024-2222)"));
        assert!(output.contains("🔴"));
        assert!(output.contains("🟠"));
        assert!(output.contains("9.8"));
        assert!(output.contains("7.5"));
    }

    #[test]
    fn test_render_informational_vulnerabilities() {
        let formatter = MarkdownFormatter::new(Locale::En);
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
        assert!(output.contains("[CVE-2024-3333](https://nvd.nist.gov/vuln/detail/CVE-2024-3333)"));
        assert!(output.contains("🟢"));
        assert!(output.contains("2.5"));
        assert!(output.contains("1.27.0"));
    }

    #[test]
    fn test_render_actionable_vulnerabilities_multiple_packages() {
        let formatter = MarkdownFormatter::new(Locale::En);
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
        let formatter = MarkdownFormatter::new(Locale::En);

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

        let formatter = MarkdownFormatter::new(Locale::En);
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

        let formatter = MarkdownFormatter::new(Locale::En);
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

        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
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
        let formatter = MarkdownFormatter::new(Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Without verification, all packages get hyperlinks
        assert!(markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("[urllib3](https://pypi.org/project/urllib3/)"));
    }

    #[test]
    fn test_format_with_empty_verified_set_no_links() {
        let model = create_test_read_model();
        let verified = HashSet::new();

        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
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
        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let markdown = formatter.format(&model).unwrap();

        // Vulnerability table should show plain text for unverified package
        assert!(!markdown.contains("[requests](https://pypi.org/project/requests/)"));
        assert!(markdown.contains("| requests |"));
    }

    #[test]
    fn test_format_package_name_with_none_verified() {
        let formatter = MarkdownFormatter::new(Locale::En);
        let result = formatter.format_package_name("requests");
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    #[test]
    fn test_format_package_name_with_verified_present() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let result = formatter.format_package_name("requests");
        assert_eq!(result, "[requests](https://pypi.org/project/requests/)");
    }

    // ============================================================
    // Vulnerability ID hyperlink tests
    // ============================================================

    #[test]
    fn test_vulnerability_id_to_link_cve() {
        assert_eq!(
            MarkdownFormatter::vulnerability_id_to_link("CVE-2024-1234"),
            "[CVE-2024-1234](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_ghsa() {
        assert_eq!(
            MarkdownFormatter::vulnerability_id_to_link("GHSA-abcd-efgh-ijkl"),
            "[GHSA-abcd-efgh-ijkl](https://github.com/advisories/GHSA-abcd-efgh-ijkl)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_pysec() {
        assert_eq!(
            MarkdownFormatter::vulnerability_id_to_link("PYSEC-2021-108"),
            "[PYSEC-2021-108](https://osv.dev/vulnerability/PYSEC-2021-108)"
        );
    }

    #[test]
    fn test_vulnerability_id_to_link_rustsec() {
        assert_eq!(
            MarkdownFormatter::vulnerability_id_to_link("RUSTSEC-2023-0001"),
            "[RUSTSEC-2023-0001](https://osv.dev/vulnerability/RUSTSEC-2023-0001)"
        );
    }

    #[test]
    fn test_format_package_name_with_verified_absent() {
        let verified = HashSet::new();
        let formatter = MarkdownFormatter::with_verified_packages(verified, Locale::En);
        let result = formatter.format_package_name("nonexistent-pkg");
        assert_eq!(result, "nonexistent-pkg");
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
}
