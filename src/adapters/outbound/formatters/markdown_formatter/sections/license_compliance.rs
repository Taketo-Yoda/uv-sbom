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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        LicenseComplianceSummary, LicenseComplianceView, LicenseViolationView, LicenseWarningView,
    };
    use crate::i18n::{Locale, Messages};

    fn make_compliance(
        violations: Vec<LicenseViolationView>,
        warnings: Vec<LicenseWarningView>,
    ) -> LicenseComplianceView {
        let violation_count = violations.len();
        let warning_count = warnings.len();
        LicenseComplianceView {
            has_violations: violation_count > 0,
            summary: LicenseComplianceSummary {
                violation_count,
                warning_count,
            },
            violations,
            warnings,
        }
    }

    fn make_violation(
        package: &str,
        version: &str,
        license: &str,
        reason: &str,
        pattern: Option<&str>,
    ) -> LicenseViolationView {
        LicenseViolationView {
            package_name: package.to_string(),
            package_version: version.to_string(),
            license: license.to_string(),
            reason: reason.to_string(),
            matched_pattern: pattern.map(|s| s.to_string()),
        }
    }

    fn make_warning(package: &str, version: &str) -> LicenseWarningView {
        LicenseWarningView {
            package_name: package.to_string(),
            package_version: version.to_string(),
        }
    }

    fn call_render(locale: Locale, compliance: &LicenseComplianceView) -> String {
        let messages = Messages::for_locale(locale);
        let mut output = String::new();
        render(messages, &mut output, compliance);
        output
    }

    // --- section header ---

    #[test]
    fn test_section_header_en() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("## License Compliance Report"));
    }

    #[test]
    fn test_section_header_ja() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("## ライセンスコンプライアンスレポート"));
    }

    // --- zero-violation edge case ---

    #[test]
    fn test_zero_violations_shows_no_violations_label_en() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("**No license violations found.**"));
    }

    #[test]
    fn test_zero_violations_shows_no_violations_label_ja() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("**ライセンス違反は見つかりませんでした。**"));
    }

    #[test]
    fn test_zero_violations_no_violations_table() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(!output.contains("### Violations"));
    }

    // --- violation count summary (singular/plural) ---

    #[test]
    fn test_single_violation_count_singular_en() {
        let v = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", Some("GPL*"));
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("**1 license violation found.**"));
    }

    #[test]
    fn test_multiple_violations_count_plural_en() {
        let v1 = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", Some("GPL*"));
        let v2 = make_violation("pkg-b", "2.0.0", "AGPL-3.0", "Copyleft", None);
        let compliance = make_compliance(vec![v1, v2], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("**2 license violations found.**"));
    }

    #[test]
    fn test_single_violation_count_ja() {
        let v = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", Some("GPL*"));
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("**1 件のライセンス違反が見つかりました。**"));
    }

    #[test]
    fn test_multiple_violations_count_ja() {
        let v1 = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", Some("GPL*"));
        let v2 = make_violation("pkg-b", "2.0.0", "AGPL-3.0", "Copyleft", None);
        let compliance = make_compliance(vec![v1, v2], vec![]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("**2 件のライセンス違反が見つかりました。**"));
    }

    // --- violations table rows ---

    #[test]
    fn test_violations_table_contains_package_info() {
        let v = make_violation(
            "requests",
            "2.31.0",
            "GPL-3.0",
            "Copyleft license",
            Some("GPL*"),
        );
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("requests"));
        assert!(output.contains("2.31.0"));
        assert!(output.contains("GPL-3.0"));
        assert!(output.contains("Copyleft license"));
        assert!(output.contains("GPL*"));
    }

    #[test]
    fn test_violations_table_no_matched_pattern_shows_dash() {
        let v = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", None);
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("| - |"));
    }

    #[test]
    fn test_violations_table_header_en() {
        let v = make_violation("pkg-a", "1.0.0", "GPL-3.0", "Copyleft", None);
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("### Violations"));
        assert!(output.contains("| Package | Version | License | Reason | Matched Pattern |"));
    }

    #[test]
    fn test_violations_table_header_ja() {
        let v = make_violation("pkg-a", "1.0.0", "GPL-3.0", "コピーレフト", None);
        let compliance = make_compliance(vec![v], vec![]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("### 違反"));
        assert!(
            output.contains("| パッケージ | バージョン | ライセンス | 理由 | マッチしたパターン |")
        );
    }

    // --- warnings table ---

    #[test]
    fn test_warnings_section_not_rendered_when_empty() {
        let compliance = make_compliance(vec![], vec![]);
        let output = call_render(Locale::En, &compliance);
        assert!(!output.contains("### Warnings"));
    }

    #[test]
    fn test_warnings_single_package_singular_en() {
        let w = make_warning("unknown-pkg", "0.1.0");
        let compliance = make_compliance(vec![], vec![w]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("**1 package with unknown license.**"));
    }

    #[test]
    fn test_warnings_multiple_packages_plural_en() {
        let w1 = make_warning("pkg-a", "1.0.0");
        let w2 = make_warning("pkg-b", "2.0.0");
        let compliance = make_compliance(vec![], vec![w1, w2]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("**2 packages with unknown license.**"));
    }

    #[test]
    fn test_warnings_count_ja() {
        let w1 = make_warning("pkg-a", "1.0.0");
        let w2 = make_warning("pkg-b", "2.0.0");
        let compliance = make_compliance(vec![], vec![w1, w2]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("**2個のライセンス不明パッケージがあります。**"));
    }

    #[test]
    fn test_warnings_table_contains_package_info() {
        let w = make_warning("unknown-pkg", "0.1.0");
        let compliance = make_compliance(vec![], vec![w]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("unknown-pkg"));
        assert!(output.contains("0.1.0"));
    }

    #[test]
    fn test_warnings_header_en() {
        let w = make_warning("unknown-pkg", "0.1.0");
        let compliance = make_compliance(vec![], vec![w]);
        let output = call_render(Locale::En, &compliance);
        assert!(output.contains("### Warnings"));
    }

    #[test]
    fn test_warnings_header_ja() {
        let w = make_warning("unknown-pkg", "0.1.0");
        let compliance = make_compliance(vec![], vec![w]);
        let output = call_render(Locale::Ja, &compliance);
        assert!(output.contains("### 警告"));
    }
}
