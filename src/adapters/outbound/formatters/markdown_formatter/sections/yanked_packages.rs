use crate::application::read_models::YankedPackagesReport;
use crate::i18n::Messages;

const REASON_MAX_LEN: usize = 100;

pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    report: &YankedPackagesReport,
) {
    output.push('\n');
    output.push_str(messages.section_yanked_packages);
    output.push_str("\n\n");
    output.push_str(messages.desc_yanked_packages);
    output.push_str("\n\n");

    if report.packages.is_empty() {
        output.push_str(messages.label_no_yanked_packages);
        output.push('\n');
        return;
    }

    output.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n",
        messages.col_package,
        messages.col_version,
        messages.col_type,
        messages.col_yanked_reason,
        messages.col_status,
    ));
    output.push_str(&super::super::table::make_separator(&[
        messages.col_package,
        messages.col_version,
        messages.col_type,
        messages.col_yanked_reason,
        messages.col_status,
    ]));

    for pkg in &report.packages {
        let type_label = if pkg.is_direct {
            messages.label_direct_deps
        } else {
            messages.label_transitive_deps
        };
        let reason = match &pkg.reason {
            Some(r) => {
                let escaped = super::super::table::escape_markdown_table_cell(r);
                super::super::table::truncate_for_table(&escaped, REASON_MAX_LEN).into_owned()
            }
            None => messages.label_yanked_no_reason.to_string(),
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | ⚠️ |\n",
            super::super::table::escape_markdown_table_cell(&pkg.name),
            super::super::table::escape_markdown_table_cell(&pkg.version),
            type_label,
            reason,
        ));
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::YankedPackageView;
    use crate::i18n::{Locale, Messages};

    fn make_view(name: &str, is_direct: bool, reason: Option<&str>) -> YankedPackageView {
        YankedPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            reason: reason.map(|r| r.to_string()),
            is_direct,
        }
    }

    fn render_en(report: &YankedPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, report);
        output
    }

    fn render_ja(report: &YankedPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, report);
        output
    }

    #[test]
    fn test_empty_report_renders_all_clear_en() {
        let report = YankedPackagesReport { packages: vec![] };
        let output = render_en(&report);
        assert!(output.contains("## Yanked Packages"));
        assert!(output.contains("No yanked packages detected."));
        assert!(!output.contains("| Package |"));
    }

    #[test]
    fn test_empty_report_renders_all_clear_ja() {
        let report = YankedPackagesReport { packages: vec![] };
        let output = render_ja(&report);
        assert!(output.contains("## 取り下げ済みパッケージ"));
        assert!(output.contains("取り下げ済みパッケージは検出されませんでした。"));
        assert!(!output.contains("| パッケージ |"));
    }

    #[test]
    fn test_table_rendered_with_packages_en() {
        let report = YankedPackagesReport {
            packages: vec![make_view("requests", true, Some("security fix"))],
        };
        let output = render_en(&report);
        assert!(output.contains("## Yanked Packages"));
        assert!(output.contains("| Package | Version | Type | Reason | Status |"));
        assert!(output.contains("| requests | 1.0.0 | Direct dependencies | security fix | ⚠️ |"));
    }

    #[test]
    fn test_table_rendered_with_packages_ja() {
        let report = YankedPackagesReport {
            packages: vec![make_view("requests", true, Some("security fix"))],
        };
        let output = render_ja(&report);
        assert!(output.contains("## 取り下げ済みパッケージ"));
        assert!(output.contains("| パッケージ | バージョン | 種別 | 理由 | 状態 |"));
        assert!(output.contains("| requests | 1.0.0 | 直接依存パッケージ | security fix | ⚠️ |"));
    }

    #[test]
    fn test_direct_vs_transitive_type_label_en() {
        let report = YankedPackagesReport {
            packages: vec![
                make_view("pkg-direct", true, Some("bug")),
                make_view("pkg-transitive", false, Some("bug")),
            ],
        };
        let output = render_en(&report);
        assert!(output.contains("| pkg-direct | 1.0.0 | Direct dependencies |"));
        assert!(output.contains("| pkg-transitive | 1.0.0 | Transitive dependencies |"));
    }

    #[test]
    fn test_no_reason_shows_placeholder_en() {
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg", true, None)],
        };
        let output = render_en(&report);
        assert!(output.contains("(no reason given)"));
    }

    #[test]
    fn test_no_reason_shows_placeholder_ja() {
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg", true, None)],
        };
        let output = render_ja(&report);
        assert!(output.contains("（理由なし）"));
    }

    #[test]
    fn test_reason_with_pipe_is_escaped() {
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg", true, Some("bad|reason"))],
        };
        let output = render_en(&report);
        assert!(output.contains("bad\\|reason"));
    }

    #[test]
    fn test_reason_with_newline_is_escaped() {
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg", true, Some("line1\nline2"))],
        };
        let output = render_en(&report);
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.iter().any(|l| l.contains("line1 line2")));
    }

    #[test]
    fn test_long_reason_is_truncated() {
        let long_reason = "a".repeat(150);
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg", true, Some(&long_reason))],
        };
        let output = render_en(&report);
        let expected_truncated = format!("{}...", "a".repeat(100));
        assert!(output.contains(&expected_truncated));
    }

    #[test]
    fn test_package_name_with_pipe_is_escaped() {
        let report = YankedPackagesReport {
            packages: vec![make_view("pkg|evil", true, Some("reason"))],
        };
        let output = render_en(&report);
        assert!(output.contains("pkg\\|evil"));
    }
}
