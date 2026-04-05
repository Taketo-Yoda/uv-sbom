use crate::application::read_models::LicenseComplianceView;
use crate::i18n::Messages;

/// Renders the license compliance section
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    compliance: &LicenseComplianceView,
) {
    output.push('\n');
    output.push_str(messages.section_license_compliance);
    output.push_str("\n\n");

    // Summary
    if compliance.has_violations {
        let unit = if compliance.summary.violation_count == 1 {
            messages.label_license_violation_singular
        } else {
            messages.label_license_violation_plural
        };
        output.push_str(&format!(
            "**{} {}**\n\n",
            compliance.summary.violation_count, unit,
        ));
    } else {
        output.push_str(messages.label_no_license_violations);
        output.push_str("\n\n");
    }

    // Violations table
    if !compliance.violations.is_empty() {
        output.push_str(messages.section_violations);
        output.push_str("\n\n");
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            messages.col_package,
            messages.col_version,
            messages.col_license,
            messages.col_reason,
            messages.col_matched_pattern,
        ));
        output.push_str(&super::super::table::make_separator(&[
            messages.col_package,
            messages.col_version,
            messages.col_license,
            messages.col_reason,
            messages.col_matched_pattern,
        ]));

        for v in &compliance.violations {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                super::super::table::escape_markdown_table_cell(&v.package_name),
                super::super::table::escape_markdown_table_cell(&v.package_version),
                super::super::table::escape_markdown_table_cell(&v.license),
                super::super::table::escape_markdown_table_cell(&v.reason),
                v.matched_pattern.as_deref().unwrap_or("-"),
            ));
        }
        output.push('\n');
    }

    // Warnings table
    if !compliance.warnings.is_empty() {
        let warning_count = compliance.summary.warning_count;
        let pkg_word = if warning_count == 1 {
            messages.label_package_singular
        } else {
            messages.label_package_plural
        };
        output.push_str(messages.section_warnings);
        output.push_str("\n\n");
        output.push_str(&Messages::format(
            messages.warn_unknown_license_packages,
            &[&warning_count.to_string(), pkg_word],
        ));
        output.push_str("\n\n");
        output.push_str(&format!(
            "| {} | {} |\n",
            messages.col_package, messages.col_version,
        ));
        output.push_str(&super::super::table::make_separator(&[
            messages.col_package,
            messages.col_version,
        ]));

        for w in &compliance.warnings {
            output.push_str(&format!(
                "| {} | {} |\n",
                super::super::table::escape_markdown_table_cell(&w.package_name),
                super::super::table::escape_markdown_table_cell(&w.package_version),
            ));
        }
        output.push('\n');
    }
}
