use crate::application::read_models::{
    VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
};
use crate::i18n::Messages;
use std::collections::HashSet;

/// Renders the vulnerabilities section
pub(super) fn render_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &VulnerabilityReportView,
) {
    output.push('\n');
    output.push_str(messages.section_vuln_report);
    output.push_str("\n\n");

    // Summary section
    render_vulnerability_summary(messages, output, &vulns.summary);

    // Actionable vulnerabilities (warning section)
    if vulns.actionable.is_empty() {
        output.push_str(messages.warn_no_vuln_above_threshold);
        output.push_str("\n\n");
    } else {
        render_actionable_vulnerabilities(messages, verified_packages, output, &vulns.actionable);
    }

    // Informational vulnerabilities
    if !vulns.informational.is_empty() {
        render_informational_vulnerabilities(
            messages,
            verified_packages,
            output,
            &vulns.informational,
        );
    }

    // Attribution
    output.push_str("\n---\n\n");
    output.push_str(messages.label_osv_attribution);
    output.push('\n');
}

/// Renders vulnerability summary statistics
pub(super) fn render_vulnerability_summary(
    messages: &'static Messages,
    output: &mut String,
    summary: &VulnerabilitySummary,
) {
    let vuln_word = if summary.total_count == 1 {
        messages.label_vulnerability_singular
    } else {
        messages.label_vulnerability_plural
    };
    let pkg_word = if summary.affected_package_count == 1 {
        messages.label_package_singular
    } else {
        messages.label_package_plural
    };
    output.push_str(&Messages::format(
        messages.summary_vuln_found,
        &[
            &summary.total_count.to_string(),
            vuln_word,
            &summary.affected_package_count.to_string(),
            pkg_word,
        ],
    ));
    output.push_str("\n\n");
}

/// Renders the warning section for actionable vulnerabilities
pub(super) fn render_actionable_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &[VulnerabilityView],
) {
    let total_vulns = vulns.len();
    let unique_packages = super::helpers::count_unique_packages(vulns);
    let vuln_word = if total_vulns == 1 {
        messages.label_vulnerability_singular
    } else {
        messages.label_vulnerability_plural
    };
    let pkg_word = if unique_packages == 1 {
        messages.label_package_singular
    } else {
        messages.label_package_plural
    };

    output.push_str(&Messages::format(
        messages.warn_vuln_found,
        &[
            &total_vulns.to_string(),
            vuln_word,
            &unique_packages.to_string(),
            pkg_word,
        ],
    ));
    output.push_str("\n\n");

    output.push_str(&super::table::vuln_table_header(messages));
    output.push_str(&super::table::vuln_table_separator(messages));

    // Sort by severity (Critical first)
    let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.iter().collect();
    sorted_vulns.sort_by_key(|v| &v.severity);

    for vuln in sorted_vulns {
        render_vulnerability_row(verified_packages, output, vuln);
    }
    output.push('\n');
}

/// Renders the info section for informational vulnerabilities
pub(super) fn render_informational_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &[VulnerabilityView],
) {
    let total_vulns = vulns.len();
    let unique_packages = super::helpers::count_unique_packages(vulns);
    let vuln_word = if total_vulns == 1 {
        messages.label_vulnerability_singular
    } else {
        messages.label_vulnerability_plural
    };
    let pkg_word = if unique_packages == 1 {
        messages.label_package_singular
    } else {
        messages.label_package_plural
    };

    output.push_str(&Messages::format(
        messages.info_vuln_found,
        &[
            &total_vulns.to_string(),
            vuln_word,
            &unique_packages.to_string(),
            pkg_word,
        ],
    ));
    output.push_str("\n\n");

    output.push_str(&super::table::vuln_table_header(messages));
    output.push_str(&super::table::vuln_table_separator(messages));

    let mut sorted_vulns: Vec<&VulnerabilityView> = vulns.iter().collect();
    sorted_vulns.sort_by_key(|v| &v.severity);

    for vuln in sorted_vulns {
        render_vulnerability_row(verified_packages, output, vuln);
    }
}

/// Renders a single vulnerability row
pub(super) fn render_vulnerability_row(
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vuln: &VulnerabilityView,
) {
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
        super::links::format_package_name(&vuln.affected_component_name, verified_packages),
        super::table::escape_markdown_table_cell(&vuln.affected_version),
        super::table::escape_markdown_table_cell(fixed_version),
        cvss_display,
        severity_emoji,
        vuln.severity.as_str(),
        super::links::vulnerability_id_to_link(&vuln.id),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{SeverityView, VulnerabilitySummary, VulnerabilityView};
    use crate::i18n::{Locale, Messages};

    fn messages() -> &'static Messages {
        Messages::for_locale(Locale::En)
    }

    #[test]
    fn test_render_vulnerability_summary() {
        let summary = VulnerabilitySummary {
            total_count: 3,
            affected_package_count: 2,
        };

        let mut output = String::new();
        render_vulnerability_summary(messages(), &mut output, &summary);

        assert!(output.contains("**Found 3 vulnerabilities in 2 packages.**"));
    }

    #[test]
    fn test_render_vulnerability_summary_singular() {
        let summary = VulnerabilitySummary {
            total_count: 1,
            affected_package_count: 1,
        };

        let mut output = String::new();
        render_vulnerability_summary(messages(), &mut output, &summary);

        assert!(output.contains("**Found 1 vulnerability in 1 package.**"));
    }

    #[test]
    fn test_render_actionable_vulnerabilities() {
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
        render_actionable_vulnerabilities(messages(), None, &mut output, &vulns);

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
        render_informational_vulnerabilities(messages(), None, &mut output, &vulns);

        assert!(output.contains("### ℹ️Info Found 1 vulnerability in 1 package."));
        assert!(output.contains("[CVE-2024-3333](https://nvd.nist.gov/vuln/detail/CVE-2024-3333)"));
        assert!(output.contains("🟢"));
        assert!(output.contains("2.5"));
        assert!(output.contains("1.27.0"));
    }

    #[test]
    fn test_render_actionable_vulnerabilities_multiple_packages() {
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
        render_actionable_vulnerabilities(messages(), None, &mut output, &vulns);

        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 2 packages."));
    }
}
