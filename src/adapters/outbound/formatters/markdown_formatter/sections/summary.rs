use crate::application::read_models::{
    AbandonedPackagesReport, ComponentView, LicenseComplianceView, VulnerabilityReportView,
};
use crate::i18n::Messages;

/// Renders the executive summary section
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    components: &[ComponentView],
    vulnerabilities: Option<&VulnerabilityReportView>,
    license_compliance: Option<&LicenseComplianceView>,
    abandoned_packages: Option<&AbandonedPackagesReport>,
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

    // Abandoned packages row
    match abandoned_packages {
        Some(report) => {
            let n = report.total_count();
            let abandoned_status = if n > 0 {
                has_warning = true;
                "⚠️"
            } else {
                "✅"
            };
            output.push_str(&format!(
                "| {} | {} | {} |\n",
                messages.label_abandoned_packages, n, abandoned_status
            ));
        }
        None => {
            output.push('\n');
            output.push_str(messages.label_abandoned_check_skipped);
            output.push('\n');
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::{
        AbandonedPackageView, AbandonedPackagesReport, LicenseComplianceSummary,
        LicenseComplianceView, SeverityView, VulnerabilityReportView, VulnerabilityView,
    };
    use crate::i18n::{Locale, Messages};
    use chrono::NaiveDate;

    fn make_component(is_direct: bool) -> ComponentView {
        ComponentView {
            bom_ref: String::new(),
            name: String::new(),
            version: String::new(),
            purl: String::new(),
            license: None,
            description: None,
            sha256_hash: None,
            is_direct_dependency: is_direct,
        }
    }

    fn make_vuln(severity: SeverityView) -> VulnerabilityView {
        VulnerabilityView {
            bom_ref: String::new(),
            id: String::new(),
            affected_component: String::new(),
            affected_component_name: String::new(),
            affected_version: String::new(),
            cvss_score: None,
            cvss_vector: None,
            severity,
            fixed_version: None,
            description: None,
            source_url: None,
        }
    }

    fn make_license_compliance(violation_count: usize) -> LicenseComplianceView {
        LicenseComplianceView {
            violations: vec![],
            warnings: vec![],
            has_violations: violation_count > 0,
            summary: LicenseComplianceSummary {
                violation_count,
                warning_count: 0,
            },
        }
    }

    fn render_summary(
        locale: Locale,
        components: &[ComponentView],
        vulnerabilities: Option<&VulnerabilityReportView>,
        license_compliance: Option<&LicenseComplianceView>,
    ) -> String {
        render_summary_with_abandoned(
            locale,
            components,
            vulnerabilities,
            license_compliance,
            None,
        )
    }

    fn render_summary_with_abandoned(
        locale: Locale,
        components: &[ComponentView],
        vulnerabilities: Option<&VulnerabilityReportView>,
        license_compliance: Option<&LicenseComplianceView>,
        abandoned_packages: Option<&AbandonedPackagesReport>,
    ) -> String {
        let messages = Messages::for_locale(locale);
        let mut output = String::new();
        render(
            messages,
            &mut output,
            components,
            vulnerabilities,
            license_compliance,
            abandoned_packages,
        );
        output
    }

    #[test]
    fn test_summary_section_header_en() {
        let output = render_summary(Locale::En, &[], None, None);
        assert!(output.starts_with("## Summary\n\n"));
    }

    #[test]
    fn test_summary_section_header_ja() {
        let output = render_summary(Locale::Ja, &[], None, None);
        assert!(output.starts_with("## サマリー\n\n"));
    }

    #[test]
    fn test_summary_package_counts_en() {
        let components = vec![
            make_component(true),
            make_component(true),
            make_component(false),
        ];
        let output = render_summary(Locale::En, &components, None, None);
        assert!(output.contains("| Direct dependencies | 2 | ✅ |"));
        assert!(output.contains("| Transitive dependencies | 1 | ✅ |"));
    }

    #[test]
    fn test_summary_package_counts_ja() {
        let components = vec![
            make_component(true),
            make_component(false),
            make_component(false),
        ];
        let output = render_summary(Locale::Ja, &components, None, None);
        assert!(output.contains("| 直接依存パッケージ | 1 | ✅ |"));
        assert!(output.contains("| 間接依存パッケージ | 2 | ✅ |"));
    }

    #[test]
    fn test_vuln_check_skipped_en() {
        let output = render_summary(Locale::En, &[], None, None);
        assert!(output.contains("_Vulnerability check skipped._"));
        assert!(!output.contains("Vulnerabilities (CRITICAL)"));
    }

    #[test]
    fn test_vuln_check_skipped_ja() {
        let output = render_summary(Locale::Ja, &[], None, None);
        assert!(output.contains("_脆弱性チェックはスキップされました。_"));
        assert!(!output.contains("脆弱性 (CRITICAL)"));
    }

    #[test]
    fn test_vuln_rows_present_when_check_enabled() {
        let report = VulnerabilityReportView::default();
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("| Vulnerabilities (CRITICAL) | 0 | ✅ |"));
        assert!(output.contains("| Vulnerabilities (HIGH) | 0 | ✅ |"));
        assert!(output.contains("| Vulnerabilities (MEDIUM) | 0 | ✅ |"));
        assert!(output.contains("| Vulnerabilities (LOW) | 0 | ✅ |"));
        assert!(!output.contains("_Vulnerability check skipped._"));
    }

    #[test]
    fn test_vuln_critical_status_is_error() {
        let report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::Critical)],
            ..Default::default()
        };
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("| Vulnerabilities (CRITICAL) | 1 | ❌ |"));
        assert!(output.contains("**Overall: Action required**"));
    }

    #[test]
    fn test_vuln_high_status_is_warning() {
        let report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::High)],
            ..Default::default()
        };
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("| Vulnerabilities (HIGH) | 1 | ⚠️ |"));
        assert!(output.contains("**Overall: Attention recommended**"));
    }

    #[test]
    fn test_vuln_medium_status_is_warning() {
        let report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::Medium)],
            ..Default::default()
        };
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("| Vulnerabilities (MEDIUM) | 1 | ⚠️ |"));
        assert!(output.contains("**Overall: Attention recommended**"));
    }

    #[test]
    fn test_vuln_low_status_is_warning() {
        let report = VulnerabilityReportView {
            informational: vec![make_vuln(SeverityView::Low)],
            ..Default::default()
        };
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("| Vulnerabilities (LOW) | 1 | ⚠️ |"));
        assert!(output.contains("**Overall: Attention recommended**"));
    }

    #[test]
    fn test_license_violation_status_is_error() {
        let license = make_license_compliance(2);
        let output = render_summary(Locale::En, &[], None, Some(&license));
        assert!(output.contains("| License violations | 2 | ❌ |"));
        assert!(output.contains("**Overall: Action required**"));
    }

    #[test]
    fn test_license_no_violation_status_is_ok() {
        let license = make_license_compliance(0);
        let output = render_summary(Locale::En, &[], None, Some(&license));
        assert!(output.contains("| License violations | 0 | ✅ |"));
    }

    #[test]
    fn test_overall_no_issues_en() {
        let report = VulnerabilityReportView::default();
        let license = make_license_compliance(0);
        let output = render_summary(Locale::En, &[], Some(&report), Some(&license));
        assert!(output.contains("**Overall: No issues found** ✅"));
    }

    #[test]
    fn test_overall_no_issues_ja() {
        let report = VulnerabilityReportView::default();
        let license = make_license_compliance(0);
        let output = render_summary(Locale::Ja, &[], Some(&report), Some(&license));
        assert!(output.contains("**総合判定: 問題なし** ✅"));
    }

    #[test]
    fn test_overall_action_required_ja() {
        let report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::Critical)],
            ..Default::default()
        };
        let output = render_summary(Locale::Ja, &[], Some(&report), None);
        assert!(output.contains("**総合判定: 対応が必要です**"));
    }

    #[test]
    fn test_overall_attention_recommended_ja() {
        let report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::High)],
            ..Default::default()
        };
        let output = render_summary(Locale::Ja, &[], Some(&report), None);
        assert!(output.contains("**総合判定: 注意が必要です**"));
    }

    #[test]
    fn test_license_compliance_none_shows_zero_violations() {
        let output = render_summary(Locale::En, &[], None, None);
        assert!(output.contains("| License violations | 0 | ✅ |"));
    }

    #[test]
    fn test_critical_overrides_warning_in_overall() {
        let report = VulnerabilityReportView {
            actionable: vec![
                make_vuln(SeverityView::Critical),
                make_vuln(SeverityView::High),
            ],
            ..Default::default()
        };
        let output = render_summary(Locale::En, &[], Some(&report), None);
        assert!(output.contains("**Overall: Action required**"));
        assert!(!output.contains("**Overall: Attention recommended**"));
    }

    fn make_abandoned_report(count: usize) -> AbandonedPackagesReport {
        let packages = (0..count)
            .map(|i| AbandonedPackageView {
                name: format!("pkg-{i}"),
                version: "1.0.0".to_string(),
                last_release_date: NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
                days_inactive: 800,
                is_direct: true,
            })
            .collect();
        AbandonedPackagesReport {
            packages,
            threshold_days: 730,
        }
    }

    #[test]
    fn test_abandoned_check_skipped_en() {
        let output = render_summary(Locale::En, &[], None, None);
        assert!(output.contains("_Abandoned package check skipped._"));
        assert!(!output.contains("Abandoned packages"));
    }

    #[test]
    fn test_abandoned_check_skipped_ja() {
        let output = render_summary(Locale::Ja, &[], None, None);
        assert!(output.contains("_廃止パッケージチェックはスキップされました。_"));
    }

    #[test]
    fn test_abandoned_zero_shows_ok_en() {
        let report = make_abandoned_report(0);
        let output = render_summary_with_abandoned(Locale::En, &[], None, None, Some(&report));
        assert!(output.contains("| Abandoned packages | 0 | ✅ |"));
        assert!(!output.contains("_Abandoned package check skipped._"));
    }

    #[test]
    fn test_abandoned_nonzero_shows_warning_en() {
        let report = make_abandoned_report(3);
        let output = render_summary_with_abandoned(Locale::En, &[], None, None, Some(&report));
        assert!(output.contains("| Abandoned packages | 3 | ⚠️ |"));
        assert!(output.contains("**Overall: Attention recommended**"));
    }

    #[test]
    fn test_abandoned_nonzero_shows_warning_ja() {
        let report = make_abandoned_report(2);
        let output = render_summary_with_abandoned(Locale::Ja, &[], None, None, Some(&report));
        assert!(output.contains("| 廃止パッケージ | 2 | ⚠️ |"));
        assert!(output.contains("**総合判定: 注意が必要です**"));
    }

    #[test]
    fn test_abandoned_warning_does_not_override_critical() {
        let vuln_report = VulnerabilityReportView {
            actionable: vec![make_vuln(SeverityView::Critical)],
            ..Default::default()
        };
        let abandoned = make_abandoned_report(1);
        let output = render_summary_with_abandoned(
            Locale::En,
            &[],
            Some(&vuln_report),
            None,
            Some(&abandoned),
        );
        assert!(output.contains("**Overall: Action required**"));
        assert!(!output.contains("**Overall: Attention recommended**"));
    }
}
