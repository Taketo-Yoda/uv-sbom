use crate::application::read_models::AbandonedPackagesReport;
use crate::i18n::Messages;

/// Renders the abandoned packages section
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    report: &AbandonedPackagesReport,
) {
    output.push('\n');
    output.push_str(messages.section_abandoned_packages);
    output.push_str("\n\n");
    output.push_str(messages.desc_abandoned_packages);
    output.push_str("\n\n");

    if report.packages.is_empty() {
        output.push_str(messages.label_no_abandoned_packages);
        output.push('\n');
        return;
    }

    output.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n",
        messages.col_package,
        messages.col_version,
        messages.col_last_release,
        messages.col_days_inactive,
        messages.col_type,
    ));
    output.push_str(&super::super::table::make_separator(&[
        messages.col_package,
        messages.col_version,
        messages.col_last_release,
        messages.col_days_inactive,
        messages.col_type,
    ]));

    for pkg in &report.packages {
        let type_label = if pkg.is_direct {
            messages.label_direct_deps
        } else {
            messages.label_transitive_deps
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            super::super::table::escape_markdown_table_cell(&pkg.name),
            super::super::table::escape_markdown_table_cell(&pkg.version),
            pkg.last_release_date,
            pkg.days_inactive,
            type_label,
        ));
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::AbandonedPackageView;
    use crate::i18n::{Locale, Messages};
    use chrono::NaiveDate;

    fn make_view(name: &str, days: i64, is_direct: bool) -> AbandonedPackageView {
        AbandonedPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            last_release_date: NaiveDate::from_ymd_opt(2022, 6, 15).unwrap(),
            days_inactive: days,
            is_direct,
        }
    }

    fn render_en(report: &AbandonedPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, report);
        output
    }

    fn render_ja(report: &AbandonedPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, report);
        output
    }

    #[test]
    fn test_empty_report_renders_no_packages_message_en() {
        let report = AbandonedPackagesReport::default();
        let output = render_en(&report);
        assert!(output.contains("## Abandoned Packages"));
        assert!(output.contains("No abandoned packages detected."));
        assert!(!output.contains("| Package |"));
    }

    #[test]
    fn test_empty_report_renders_no_packages_message_ja() {
        let report = AbandonedPackagesReport::default();
        let output = render_ja(&report);
        assert!(output.contains("## 廃止パッケージ"));
        assert!(output.contains("廃止パッケージは検出されませんでした。"));
        assert!(!output.contains("| パッケージ |"));
    }

    #[test]
    fn test_table_rendered_with_packages_en() {
        let report = AbandonedPackagesReport {
            packages: vec![make_view("requests", 800, true)],
            threshold_days: 730,
        };
        let output = render_en(&report);
        assert!(output.contains("## Abandoned Packages"));
        assert!(output.contains("| Package | Version | Last Release | Days Inactive | Type |"));
        assert!(output.contains("| requests | 1.0.0 | 2022-06-15 | 800 | Direct dependencies |"));
    }

    #[test]
    fn test_table_rendered_with_packages_ja() {
        let report = AbandonedPackagesReport {
            packages: vec![make_view("requests", 800, true)],
            threshold_days: 730,
        };
        let output = render_ja(&report);
        assert!(output.contains("## 廃止パッケージ"));
        assert!(output
            .contains("| パッケージ | バージョン | 最終リリース | 非アクティブ日数 | 種別 |"));
        assert!(output.contains("| requests | 1.0.0 | 2022-06-15 | 800 | 直接依存パッケージ |"));
    }

    #[test]
    fn test_direct_vs_transitive_type_label_en() {
        let report = AbandonedPackagesReport {
            packages: vec![
                make_view("pkg-direct", 900, true),
                make_view("pkg-transitive", 1000, false),
            ],
            threshold_days: 730,
        };
        let output = render_en(&report);
        assert!(output.contains("| pkg-direct | 1.0.0 | 2022-06-15 | 900 | Direct dependencies |"));
        assert!(output
            .contains("| pkg-transitive | 1.0.0 | 2022-06-15 | 1000 | Transitive dependencies |"));
    }

    #[test]
    fn test_package_name_with_pipe_is_escaped() {
        let mut pkg = make_view("pkg|evil", 800, true);
        pkg.name = "pkg|evil".to_string();
        let report = AbandonedPackagesReport {
            packages: vec![pkg],
            threshold_days: 730,
        };
        let output = render_en(&report);
        assert!(output.contains("pkg\\|evil"));
    }
}
