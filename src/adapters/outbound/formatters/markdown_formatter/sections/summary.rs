use crate::application::read_models::{
    ComponentView, LicenseComplianceView, VulnerabilityReportView,
};
use crate::i18n::Messages;

/// Renders the executive summary section
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    components: &[ComponentView],
    vulnerabilities: Option<&VulnerabilityReportView>,
    license_compliance: Option<&LicenseComplianceView>,
) {
    output.push_str(messages.section_summary);
    output.push_str("\n\n");

    // Table header
    output.push_str(&format!(
        "| {} | {} | {} |\n",
        messages.col_item, messages.col_count, messages.col_status
    ));
    output.push_str(&super::super::table::make_separator(&[
        messages.col_item,
        messages.col_count,
        messages.col_status,
    ]));

    // Package count rows
    let direct_count = components.iter().filter(|c| c.is_direct_dependency).count();
    let transitive_count = components
        .iter()
        .filter(|c| !c.is_direct_dependency)
        .count();
    output.push_str(&format!(
        "| {} | {} | ✅ |\n",
        messages.label_direct_deps, direct_count
    ));
    output.push_str(&format!(
        "| {} | {} | ✅ |\n",
        messages.label_transitive_deps, transitive_count
    ));

    // Vulnerability rows
    let mut has_critical = false;
    let mut has_warning = false;
    if let Some(vuln_report) = vulnerabilities {
        let counts = vuln_report.counts_by_severity();
        let critical_status = if counts.critical > 0 {
            has_critical = true;
            "❌"
        } else {
            "✅"
        };
        let high_status = if counts.high > 0 {
            has_warning = true;
            "⚠️"
        } else {
            "✅"
        };
        let medium_status = if counts.medium > 0 {
            has_warning = true;
            "⚠️"
        } else {
            "✅"
        };
        let low_status = if counts.low > 0 {
            has_warning = true;
            "⚠️"
        } else {
            "✅"
        };
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            messages.label_vuln_critical, counts.critical, critical_status
        ));
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            messages.label_vuln_high, counts.high, high_status
        ));
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            messages.label_vuln_medium, counts.medium, medium_status
        ));
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            messages.label_vuln_low, counts.low, low_status
        ));
    } else {
        output.push_str(&format!("\n{}\n", messages.label_vuln_check_skipped));
    }

    // License violations row
    let violation_count = license_compliance
        .map(|lc| lc.summary.violation_count)
        .unwrap_or(0);
    let license_status = if violation_count > 0 {
        has_critical = true;
        "❌"
    } else {
        "✅"
    };
    output.push_str(&format!(
        "| {} | {} | {} |\n",
        messages.label_license_violations, violation_count, license_status
    ));

    // Overall line
    output.push('\n');
    let overall = if has_critical {
        messages.overall_action_required
    } else if has_warning {
        messages.overall_attention_recommended
    } else {
        messages.overall_no_issues
    };
    output.push_str(overall);
    output.push_str("\n\n");
}
