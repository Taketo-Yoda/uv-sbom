use crate::application::read_models::{
    VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
};
use crate::i18n::Messages;
use std::collections::HashSet;

fn has_exploitability_data(
    actionable: &[VulnerabilityView],
    informational: &[VulnerabilityView],
) -> bool {
    actionable
        .iter()
        .chain(informational.iter())
        .any(|v| v.epss_percentile.is_some())
}

/// Renders the vulnerabilities section
pub(super) fn render_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &VulnerabilityReportView,
    baseline_suppressed_count: usize,
) {
    output.push('\n');
    output.push_str(messages.section_vuln_report);
    output.push_str("\n\n");

    // Malicious-package advisories get their own block and are kept out of the
    // regular tables. #1042 always places them in `actionable`; `informational`
    // is split too so a differently built read model cannot show one twice.
    let (malicious_actionable, actionable): (Vec<_>, Vec<_>) = vulns
        .actionable
        .iter()
        .cloned()
        .partition(|v| v.is_malicious);
    let (malicious_informational, informational): (Vec<_>, Vec<_>) = vulns
        .informational
        .iter()
        .cloned()
        .partition(|v| v.is_malicious);
    let malicious: Vec<&VulnerabilityView> = malicious_actionable
        .iter()
        .chain(malicious_informational.iter())
        .collect();

    // The malicious block has no EPSS/KEV columns, so only the regular tables
    // decide whether those columns and their attribution are shown.
    let show_exploitability = has_exploitability_data(&actionable, &informational);

    // Summary section
    render_vulnerability_summary(messages, output, &vulns.summary);

    if !malicious.is_empty() {
        render_malicious_vulnerabilities(messages, verified_packages, output, &malicious);
    }

    // Actionable vulnerabilities (warning section)
    if actionable.is_empty() {
        if malicious.is_empty() {
            output.push_str(messages.warn_no_vuln_above_threshold);
            output.push_str("\n\n");
        }
    } else {
        render_actionable_vulnerabilities(
            messages,
            verified_packages,
            output,
            &actionable,
            show_exploitability,
        );
    }

    // Informational vulnerabilities
    if !informational.is_empty() {
        render_informational_vulnerabilities(
            messages,
            verified_packages,
            output,
            &informational,
            show_exploitability,
        );
    }

    // Baseline suppression footnote
    if baseline_suppressed_count > 0 {
        output.push('\n');
        output.push_str(&Messages::format(
            messages.footnote_baseline_suppressed,
            &[&baseline_suppressed_count.to_string()],
        ));
        output.push('\n');
    }

    // Attribution
    output.push_str("\n---\n\n");
    output.push_str(messages.label_osv_attribution);
    output.push('\n');
    if show_exploitability {
        output.push_str(messages.label_epss_kev_attribution);
        output.push('\n');
    }
}

/// Renders the block for OSV malicious-package (`MAL-`) advisories.
///
/// Severity, CVSS and EPSS/KEV are omitted: malware has no meaningful score,
/// and showing "NONE" would understate it.
fn render_malicious_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &[&VulnerabilityView],
) {
    output.push_str(messages.warn_malicious_found);
    output.push_str("\n\n");
    output.push_str(messages.action_remove_malicious);
    output.push_str("\n\n");

    output.push_str(&format!(
        "| {} | {} | {} | {} |\n",
        messages.col_package,
        messages.col_current_version,
        messages.col_vuln_id,
        messages.col_description,
    ));
    output.push_str(&super::table::make_separator(&[
        messages.col_package,
        messages.col_current_version,
        messages.col_vuln_id,
        messages.col_description,
    ]));

    for vuln in vulns {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            super::links::format_package_name(&vuln.affected_component_name, verified_packages),
            super::table::escape_markdown_table_cell(&vuln.affected_version),
            super::links::vulnerability_id_to_link(&vuln.id),
            advisory_summary_cell(vuln.description.as_deref()),
        ));
    }
    output.push('\n');
}

/// Formats an untrusted OSV advisory summary as a single Markdown table cell.
///
/// Whitespace runs (including `\r`, which `escape_markdown_table_cell` keeps)
/// collapse to one space, so the row stays on one line. The text is truncated
/// before it is escaped, so truncation cannot split an escaped `\|`.
fn advisory_summary_cell(summary: Option<&str>) -> String {
    let normalized = summary
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    if normalized.is_empty() {
        return "-".to_string();
    }
    let truncated =
        super::table::truncate_for_table(&normalized, super::table::ADVISORY_SUMMARY_MAX_LEN);
    super::table::escape_markdown_table_cell(&truncated)
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
    show_exploitability: bool,
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

    output.push_str(&super::table::vuln_table_header_with_exploitability(
        messages,
        show_exploitability,
    ));
    output.push_str(&super::table::vuln_table_separator_with_exploitability(
        messages,
        show_exploitability,
    ));

    for vuln in vulns {
        render_vulnerability_row(verified_packages, output, vuln, show_exploitability);
    }
    output.push('\n');
}

/// Renders the info section for informational vulnerabilities
pub(super) fn render_informational_vulnerabilities(
    messages: &'static Messages,
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vulns: &[VulnerabilityView],
    show_exploitability: bool,
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

    output.push_str(&super::table::vuln_table_header_with_exploitability(
        messages,
        show_exploitability,
    ));
    output.push_str(&super::table::vuln_table_separator_with_exploitability(
        messages,
        show_exploitability,
    ));

    for vuln in vulns {
        render_vulnerability_row(verified_packages, output, vuln, show_exploitability);
    }
}

/// Renders a single vulnerability row
pub(super) fn render_vulnerability_row(
    verified_packages: Option<&HashSet<String>>,
    output: &mut String,
    vuln: &VulnerabilityView,
    show_exploitability: bool,
) {
    let cvss_display = vuln
        .cvss_score
        .map_or("N/A".to_string(), |s| format!("{:.1}", s));
    let fixed_version = vuln.fixed_version.as_deref().unwrap_or("N/A");
    let severity_emoji = vuln.severity.emoji();

    output.push_str(&format!(
        "| {} | {} | {} | {} | {} {} | {} |",
        super::links::format_package_name(&vuln.affected_component_name, verified_packages),
        super::table::escape_markdown_table_cell(&vuln.affected_version),
        super::table::escape_markdown_table_cell(fixed_version),
        cvss_display,
        severity_emoji,
        vuln.severity.as_str(),
        super::links::vulnerability_id_to_link(&vuln.id),
    ));

    if show_exploitability {
        let kev_display = vuln
            .in_kev
            .map_or("-", |kev| if kev { "Yes" } else { "No" });
        let epss_display = vuln
            .epss_percentile
            .map(format_epss_percentile)
            .unwrap_or_else(|| "-".to_string());
        output.push_str(&format!(" {} | {} |", kev_display, epss_display));
    }
    output.push('\n');
}

pub(super) fn format_epss_percentile(percentile: f32) -> String {
    let pct = (percentile * 100.0).round() as u32;
    let suffix = ordinal_suffix(pct);
    format!("{}{} percentile", pct, suffix)
}

fn ordinal_suffix(n: u32) -> &'static str {
    if (11..=13).contains(&(n % 100)) {
        return "th";
    }
    match n % 10 {
        1 => "st",
        2 => "nd",
        3 => "rd",
        _ => "th",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        SeverityView, VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
    };
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
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
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
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
            },
        ];

        let mut output = String::new();
        render_actionable_vulnerabilities(messages(), None, &mut output, &vulns, false);

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
            epss_percentile: None,
            in_kev: None,
            is_malicious: false,
        }];

        let mut output = String::new();
        render_informational_vulnerabilities(messages(), None, &mut output, &vulns, false);

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
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
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
                epss_percentile: None,
                in_kev: None,
                is_malicious: false,
            },
        ];

        let mut output = String::new();
        render_actionable_vulnerabilities(messages(), None, &mut output, &vulns, false);

        assert!(output.contains("### ⚠️Warning Found 2 vulnerabilities in 2 packages."));
    }

    #[test]
    fn test_render_vulnerability_row_with_exploitability() {
        let vuln = VulnerabilityView {
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
            epss_percentile: Some(0.97),
            in_kev: Some(true),
            is_malicious: false,
        };

        let mut output = String::new();
        render_vulnerability_row(None, &mut output, &vuln, true);

        assert!(output.contains("Yes"));
        assert!(output.contains("97th percentile"));
    }

    #[test]
    fn test_render_vulnerability_row_without_exploitability() {
        let vuln = VulnerabilityView {
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
            epss_percentile: None,
            in_kev: None,
            is_malicious: false,
        };

        let mut output = String::new();
        render_vulnerability_row(None, &mut output, &vuln, false);

        assert!(!output.contains("percentile"));
        assert!(!output.contains("Yes"));
    }

    fn make_vuln(
        id: &str,
        name: &str,
        version: &str,
        severity: SeverityView,
        is_malicious: bool,
        epss_percentile: Option<f32>,
    ) -> VulnerabilityView {
        VulnerabilityView {
            bom_ref: format!("vuln-{id}"),
            id: id.to_string(),
            affected_component: format!("pkg:pypi/{name}@{version}"),
            affected_component_name: name.to_string(),
            affected_version: version.to_string(),
            cvss_score: if is_malicious { None } else { Some(9.8) },
            cvss_vector: None,
            severity,
            fixed_version: None,
            description: None,
            source_url: None,
            epss_percentile,
            in_kev: epss_percentile.map(|_| false),
            is_malicious,
        }
    }

    fn report(
        actionable: Vec<VulnerabilityView>,
        informational: Vec<VulnerabilityView>,
    ) -> VulnerabilityReportView {
        VulnerabilityReportView {
            summary: VulnerabilitySummary {
                total_count: actionable.len() + informational.len(),
                affected_package_count: 1,
            },
            actionable,
            informational,
        }
    }

    fn render(messages: &'static Messages, vulns: &VulnerabilityReportView) -> String {
        let mut output = String::new();
        render_vulnerabilities(messages, None, &mut output, vulns, 0);
        output
    }

    #[test]
    fn test_render_vulnerabilities_without_malicious_is_unchanged() {
        let vulns = report(
            vec![make_vuln(
                "CVE-2024-1111",
                "requests",
                "2.31.0",
                SeverityView::Critical,
                false,
                None,
            )],
            vec![make_vuln(
                "CVE-2024-3333",
                "requests",
                "2.31.0",
                SeverityView::Low,
                false,
                None,
            )],
        );

        let expected = "\n## Vulnerability Report\n\n\
**Found 2 vulnerabilities in 1 package.**\n\n\
### ⚠️Warning Found 1 vulnerability in 1 package.\n\n\
| Package | Current Version | Fixed Version | CVSS | Severity | Vulnerability ID |\n\
|---------|-----------------|---------------|------|----------|------------------|\n\
| [requests](https://pypi.org/project/requests/) | 2.31.0 | N/A | 9.8 | 🔴 CRITICAL | [CVE-2024-1111](https://nvd.nist.gov/vuln/detail/CVE-2024-1111) |\n\
\n\
### ℹ️Info Found 1 vulnerability in 1 package.\n\n\
| Package | Current Version | Fixed Version | CVSS | Severity | Vulnerability ID |\n\
|---------|-----------------|---------------|------|----------|------------------|\n\
| [requests](https://pypi.org/project/requests/) | 2.31.0 | N/A | 9.8 | 🟢 LOW | [CVE-2024-3333](https://nvd.nist.gov/vuln/detail/CVE-2024-3333) |\n\
\n---\n\n";
        let output = render(messages(), &vulns);
        assert!(output.starts_with(expected), "unexpected output:\n{output}");
        assert_eq!(
            output,
            format!("{expected}{}\n", messages().label_osv_attribution)
        );
    }

    #[test]
    fn test_render_vulnerabilities_without_malicious_empty_actionable_is_unchanged() {
        let vulns = report(vec![], vec![]);
        let output = render(messages(), &vulns);
        assert_eq!(
            output,
            format!(
                "\n## Vulnerability Report\n\n\
**Found 0 vulnerabilities in 1 package.**\n\n\
### ⚠️Warning No vulnerabilities found above threshold.\n\n\
\n---\n\n{}\n",
                messages().label_osv_attribution
            )
        );
    }

    #[test]
    fn test_render_malicious_block_en() {
        let vulns = report(
            vec![make_vuln(
                "MAL-2024-1234",
                "evil-pkg",
                "1.0.0",
                SeverityView::None,
                true,
                None,
            )],
            vec![],
        );

        let output = render(messages(), &vulns);

        assert!(output.contains(
            "### 🚨Alert Malicious packages detected.\n\n\
Remove these packages and rotate any credentials they may have accessed.\n\n\
| Package | Current Version | Vulnerability ID | Description |\n\
|---------|-----------------|------------------|-------------|\n\
| [evil-pkg](https://pypi.org/project/evil-pkg/) | 1.0.0 | [MAL-2024-1234](https://osv.dev/vulnerability/MAL-2024-1234) | - |\n"
        ));
        assert!(!output.contains("NONE"));
    }

    #[test]
    fn test_render_malicious_block_ja() {
        let vulns = report(
            vec![make_vuln(
                "MAL-2024-1234",
                "evil-pkg",
                "1.0.0",
                SeverityView::None,
                true,
                None,
            )],
            vec![],
        );

        let ja = Messages::for_locale(Locale::Ja);
        let output = render(ja, &vulns);

        assert!(output.contains("### 🚨危険 悪意のあるパッケージが検出されました。"));
        assert!(output.contains(
            "このパッケージを削除し、アクセスされた可能性のある認証情報をすべてローテーションしてください。"
        ));
        assert!(output.contains("[MAL-2024-1234](https://osv.dev/vulnerability/MAL-2024-1234)"));
        assert!(!output.contains(ja.warn_no_vuln_above_threshold));
    }

    fn malicious_with_summary(summary: &str) -> VulnerabilityReportView {
        let mut vuln = make_vuln(
            "MAL-2024-1234",
            "evil-pkg",
            "1.0.0",
            SeverityView::None,
            true,
            None,
        );
        vuln.description = Some(summary.to_string());
        report(vec![vuln], vec![])
    }

    #[test]
    fn test_render_malicious_block_shows_summary_en() {
        let output = render(
            messages(),
            &malicious_with_summary("Malicious code in evil-pkg (PyPI)"),
        );

        assert!(output.contains(
            "| [evil-pkg](https://pypi.org/project/evil-pkg/) | 1.0.0 | \
[MAL-2024-1234](https://osv.dev/vulnerability/MAL-2024-1234) | \
Malicious code in evil-pkg (PyPI) |\n"
        ));
    }

    #[test]
    fn test_render_malicious_block_shows_summary_ja() {
        let ja = Messages::for_locale(Locale::Ja);
        let output = render(
            ja,
            &malicious_with_summary("Malicious code in evil-pkg (PyPI)"),
        );

        assert!(output.contains("| パッケージ | "));
        assert!(output.contains(" | 説明 |\n"));
        assert!(output.contains(" | Malicious code in evil-pkg (PyPI) |\n"));
    }

    #[test]
    fn test_advisory_summary_cell_none_is_dash() {
        assert_eq!(advisory_summary_cell(None), "-");
    }

    #[test]
    fn test_advisory_summary_cell_whitespace_only_is_dash() {
        assert_eq!(advisory_summary_cell(Some(" \r\n\t ")), "-");
    }

    #[test]
    fn test_advisory_summary_cell_escapes_pipes_and_line_breaks() {
        assert_eq!(advisory_summary_cell(Some("a|b\nc\r\nd")), "a\\|b c d");
    }

    #[test]
    fn test_render_malicious_block_summary_keeps_row_on_one_line() {
        let output = render(messages(), &malicious_with_summary("a|b\nc\r\nd"));

        let row = output
            .lines()
            .find(|line| line.contains("MAL-2024-1234"))
            .unwrap();
        assert!(row.ends_with(" | a\\|b c d |"));
        assert!(!output.contains('\r'));
    }

    #[test]
    fn test_advisory_summary_cell_truncates_long_text() {
        let summary = "x".repeat(150);

        let cell = advisory_summary_cell(Some(&summary));

        assert_eq!(cell, format!("{}...", "x".repeat(100)));
    }

    #[test]
    fn test_advisory_summary_cell_truncation_does_not_split_escaped_pipe() {
        // The 100th character is a pipe: it is kept whole and escaped.
        let summary = format!("{}|{}", "x".repeat(99), "y".repeat(10));

        let cell = advisory_summary_cell(Some(&summary));

        assert_eq!(cell, format!("{}\\|...", "x".repeat(99)));
    }

    #[test]
    fn test_render_malicious_block_before_actionable_and_not_duplicated() {
        let vulns = report(
            vec![
                make_vuln(
                    "CVE-2024-1111",
                    "requests",
                    "2.31.0",
                    SeverityView::Critical,
                    false,
                    None,
                ),
                make_vuln(
                    "MAL-2024-1234",
                    "evil-pkg",
                    "1.0.0",
                    SeverityView::None,
                    true,
                    None,
                ),
            ],
            vec![make_vuln(
                "MAL-2024-5678",
                "evil-pkg",
                "1.0.0",
                SeverityView::None,
                true,
                None,
            )],
        );

        let output = render(messages(), &vulns);

        let block = output.find("### 🚨Alert").expect("malicious block");
        let actionable = output
            .find("### ⚠️Warning Found")
            .expect("actionable table");
        assert!(block < actionable);
        // Only the non-malicious entry is counted in the actionable table.
        assert!(output.contains("### ⚠️Warning Found 1 vulnerability in 1 package."));
        assert_eq!(output.matches("MAL-2024-1234](").count(), 1);
        assert_eq!(output.matches("MAL-2024-5678](").count(), 1);
        assert!(!output.contains("### ℹ️Info"));
    }

    #[test]
    fn test_render_only_malicious_omits_no_vuln_above_threshold() {
        let vulns = report(
            vec![make_vuln(
                "MAL-2024-1234",
                "evil-pkg",
                "1.0.0",
                SeverityView::None,
                true,
                None,
            )],
            vec![],
        );

        let output = render(messages(), &vulns);

        assert!(output.contains("### 🚨Alert"));
        assert!(!output.contains(messages().warn_no_vuln_above_threshold));
        assert!(!output.contains("### ⚠️Warning"));
    }

    #[test]
    fn test_render_malicious_epss_does_not_enable_exploitability_columns() {
        let vulns = report(
            vec![
                make_vuln(
                    "CVE-2024-1111",
                    "requests",
                    "2.31.0",
                    SeverityView::Critical,
                    false,
                    None,
                ),
                make_vuln(
                    "MAL-2024-1234",
                    "evil-pkg",
                    "1.0.0",
                    SeverityView::None,
                    true,
                    Some(0.5),
                ),
            ],
            vec![],
        );

        let output = render(messages(), &vulns);

        assert!(!output.contains(messages().col_epss));
        assert!(!output.contains(messages().label_epss_kev_attribution));
    }

    #[test]
    fn test_render_regular_epss_still_enables_exploitability_columns() {
        let vulns = report(
            vec![make_vuln(
                "CVE-2024-1111",
                "requests",
                "2.31.0",
                SeverityView::Critical,
                false,
                Some(0.97),
            )],
            vec![],
        );

        let output = render(messages(), &vulns);

        assert!(output.contains("97th percentile"));
        assert!(output.contains(messages().label_epss_kev_attribution));
    }

    #[test]
    fn test_format_epss_percentile_ordinals() {
        assert_eq!(format_epss_percentile(0.97), "97th percentile");
        assert_eq!(format_epss_percentile(0.01), "1st percentile");
        assert_eq!(format_epss_percentile(0.02), "2nd percentile");
        assert_eq!(format_epss_percentile(0.03), "3rd percentile");
        assert_eq!(format_epss_percentile(0.11), "11th percentile");
        assert_eq!(format_epss_percentile(0.12), "12th percentile");
        assert_eq!(format_epss_percentile(0.13), "13th percentile");
        assert_eq!(format_epss_percentile(0.21), "21st percentile");
        assert_eq!(format_epss_percentile(1.0), "100th percentile");
        assert_eq!(format_epss_percentile(0.0), "0th percentile");
    }
}
