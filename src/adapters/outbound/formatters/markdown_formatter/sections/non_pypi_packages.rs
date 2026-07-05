use crate::application::read_models::NonPyPiPackagesReport;
use crate::i18n::Messages;

/// Renders the non-PyPI packages section.
///
/// Callers MUST check `report.is_empty()` before calling this function and skip
/// the call entirely when empty — unlike the abandoned-packages section, there is
/// no empty-state message here, and this function does not guard against an empty
/// report itself; calling it with one produces a misleading "0 packages" section.
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    report: &NonPyPiPackagesReport,
) {
    output.push('\n');
    output.push_str(messages.section_non_pypi_packages);
    output.push_str("\n\n");
    output.push_str(&Messages::format(
        messages.summary_non_pypi_packages,
        &[
            &report.total_count().to_string(),
            &report.direct_count().to_string(),
            &report.transitive_count().to_string(),
        ],
    ));
    output.push_str("\n\n");

    output.push_str(&format!(
        "| {} | {} | {} | {} |\n",
        messages.col_package, messages.col_version, messages.col_source_type, messages.col_source,
    ));
    output.push_str(&super::super::table::make_separator(&[
        messages.col_package,
        messages.col_version,
        messages.col_source_type,
        messages.col_source,
    ]));

    for pkg in &report.packages {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            super::super::table::escape_markdown_table_cell(&pkg.name),
            super::super::table::escape_markdown_table_cell(&pkg.version),
            super::super::table::escape_markdown_table_cell(&pkg.source_label),
            super::super::table::escape_markdown_table_cell(&pkg.source_location),
        ));
    }
    output.push('\n');

    output.push_str(messages.note_non_pypi_packages);
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::NonPyPiPackageView;
    use crate::i18n::{Locale, Messages};

    fn make_view(
        name: &str,
        source_label: &str,
        source_location: &str,
        is_direct: bool,
    ) -> NonPyPiPackageView {
        NonPyPiPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source_label: source_label.to_string(),
            source_location: source_location.to_string(),
            is_direct,
        }
    }

    fn render_en(report: &NonPyPiPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, report);
        output
    }

    fn render_ja(report: &NonPyPiPackagesReport) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, report);
        output
    }

    #[test]
    fn test_section_rendered_with_correct_rows_en() {
        let report = NonPyPiPackagesReport {
            packages: vec![
                make_view(
                    "my-internal-lib",
                    "Private Registry",
                    "https://internal.company.com/simple",
                    true,
                ),
                make_view(
                    "dev-tool",
                    "Git",
                    "https://github.com/user/repo?rev=abc123",
                    false,
                ),
            ],
        };
        let output = render_en(&report);
        assert!(output.contains("## ⚠️ Non-PyPI Package Sources"));
        assert!(output.contains(
            "2 packages are sourced from outside the official PyPI registry (1 direct, 1 transitive)."
        ));
        assert!(output.contains("| Package | Version | Source Type | Source |"));
        assert!(output.contains(
            "| my-internal-lib | 1.0.0 | Private Registry | https://internal.company.com/simple |"
        ));
        assert!(
            output.contains("| dev-tool | 1.0.0 | Git | https://github.com/user/repo?rev=abc123 |")
        );
        assert!(output.contains(
            "> Packages from non-PyPI sources may not be subject to PyPI's security policies."
        ));
    }

    #[test]
    fn test_section_rendered_ja() {
        let report = NonPyPiPackagesReport {
            packages: vec![make_view(
                "my-internal-lib",
                "Private Registry",
                "https://internal.company.com/simple",
                true,
            )],
        };
        let output = render_ja(&report);
        assert!(output.contains("## ⚠️ PyPI以外のパッケージソース"));
        assert!(output.contains("1個のパッケージが公式PyPIレジストリ以外から取得されています（直接依存 1件、間接依存 0件）。"));
        assert!(output.contains("| パッケージ | バージョン | ソース種別 | 取得元 |"));
        assert!(output.contains("PyPI以外のソースから取得されたパッケージは"));
    }

    #[test]
    fn test_direct_and_transitive_counts_shown() {
        let report = NonPyPiPackagesReport {
            packages: vec![
                make_view("a", "Git", "https://example.com/a", true),
                make_view("b", "Git", "https://example.com/b", false),
                make_view("c", "Git", "https://example.com/c", false),
            ],
        };
        let output = render_en(&report);
        assert!(output.contains(
            "3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive)."
        ));
    }

    #[test]
    fn test_package_name_with_pipe_is_escaped() {
        let report = NonPyPiPackagesReport {
            packages: vec![make_view(
                "pkg|evil",
                "Git",
                "https://example.com/pkg",
                true,
            )],
        };
        let output = render_en(&report);
        assert!(output.contains("pkg\\|evil"));
    }
}
