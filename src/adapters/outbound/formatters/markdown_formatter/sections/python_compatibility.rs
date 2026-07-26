use crate::application::read_models::PythonCompatibilityReport;
use crate::i18n::Messages;

/// Renders the Python version compatibility section.
///
/// Unlike `non_pypi_packages`, callers do NOT need to check `report.is_empty()`
/// before calling this function: an empty report is a meaningful "all clear"
/// result and renders its own heading, distinct from the "issues found" heading.
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    report: &PythonCompatibilityReport,
) {
    output.push('\n');

    if report.is_empty() {
        output.push_str(&Messages::format(
            messages.section_python_compat_ok,
            &[&report.target_python],
        ));
        output.push_str("\n\n");
        output.push_str(messages.label_python_compat_all_clear);
        output.push('\n');
        return;
    }

    output.push_str(&Messages::format(
        messages.section_python_compat_issues,
        &[&report.target_python],
    ));
    output.push_str("\n\n");
    output.push_str(&Messages::format(
        messages.summary_python_compat_issues,
        &[
            &report.total_count().to_string(),
            &report.direct_count().to_string(),
            &report.transitive_count().to_string(),
        ],
    ));
    output.push_str("\n\n");

    output.push_str(&format!(
        "| {} | {} | {} | {} |\n",
        messages.col_package, messages.col_version, messages.col_requires_python, messages.col_type,
    ));
    output.push_str(&super::super::table::make_separator(&[
        messages.col_package,
        messages.col_version,
        messages.col_requires_python,
        messages.col_type,
    ]));

    for pkg in &report.incompatible {
        let type_label = if pkg.is_direct {
            messages.label_direct_deps
        } else {
            messages.label_transitive_deps
        };
        let requires_python = pkg
            .requires_python
            .as_deref()
            .map(super::super::table::escape_markdown_table_cell)
            .unwrap_or_else(|| "—".to_string());
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            super::super::table::escape_markdown_table_cell(&pkg.name),
            super::super::table::escape_markdown_table_cell(&pkg.version),
            requires_python,
            type_label,
        ));
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::PythonIncompatibilityView;
    use crate::i18n::{Locale, Messages};

    fn make_view(
        name: &str,
        requires_python: Option<&str>,
        is_direct: bool,
    ) -> PythonIncompatibilityView {
        PythonIncompatibilityView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            requires_python: requires_python.map(str::to_string),
            is_direct,
        }
    }

    fn render_en(report: &PythonCompatibilityReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, report);
        output
    }

    fn render_ja(report: &PythonCompatibilityReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, report);
        output
    }

    #[test]
    fn test_issues_table_rendered_en() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![
                make_view("legacy-lib", Some(">=3.8,<3.12"), true),
                make_view("old-dep", Some(">=3.9,<3.12"), false),
            ],
        };
        let output = render_en(&report);
        assert!(output.contains("## ⚠️ Python 3.13 Compatibility Issues"));
        assert!(output.contains(
            "2 package(s) incompatible with the target Python version (1 direct, 1 transitive)."
        ));
        assert!(output.contains("| Package | Version | Requires-Python | Type |"));
        assert!(output.contains("| legacy-lib | 1.0.0 | >=3.8,<3.12 | Direct dependencies |"));
        assert!(output.contains("| old-dep | 1.0.0 | >=3.9,<3.12 | Transitive dependencies |"));
    }

    #[test]
    fn test_issues_table_rendered_ja() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![make_view("legacy-lib", Some(">=3.8,<3.12"), true)],
        };
        let output = render_ja(&report);
        assert!(output.contains("## ⚠️ Python 3.13 互換性の問題"));
        assert!(output.contains(
            "1個のパッケージがターゲットPythonバージョンと非互換です（直接依存 1件、間接依存 0件）。"
        ));
        assert!(output.contains("| パッケージ | バージョン | Requires-Python | 種別 |"));
        assert!(output.contains("| legacy-lib | 1.0.0 | >=3.8,<3.12 | 直接依存パッケージ |"));
    }

    #[test]
    fn test_all_clear_rendered_en() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![],
        };
        let output = render_en(&report);
        assert!(output.contains("## ✅ Python 3.13 Compatibility"));
        assert!(output.contains("All packages are compatible with the target Python version."));
        assert!(!output.contains("| Package |"));
    }

    #[test]
    fn test_all_clear_rendered_ja() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![],
        };
        let output = render_ja(&report);
        assert!(output.contains("## ✅ Python 3.13 互換性"));
        assert!(
            output.contains("すべてのパッケージがターゲットPythonバージョンと互換性があります。")
        );
        assert!(!output.contains("| Package |"));
    }

    #[test]
    fn test_missing_requires_python_renders_placeholder() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![make_view("no-constraint-lib", None, true)],
        };
        let output = render_en(&report);
        assert!(output.contains("| no-constraint-lib | 1.0.0 | — | Direct dependencies |"));
    }

    #[test]
    fn test_package_name_with_pipe_is_escaped() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![make_view("pkg|evil", Some(">=3.9"), true)],
        };
        let output = render_en(&report);
        assert!(output.contains("pkg\\|evil"));
    }
}
