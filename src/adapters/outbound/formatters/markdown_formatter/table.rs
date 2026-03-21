use crate::i18n::Messages;

/// Escapes pipe characters and newlines for safe Markdown table rendering
pub(super) fn escape_markdown_table_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// Generates a Markdown table separator row from column header strings.
/// Each separator cell width matches the header's char count plus two spaces.
pub(super) fn make_separator(cols: &[&str]) -> String {
    let mut sep = String::from("|");
    for col in cols {
        let dashes = "-".repeat(col.chars().count() + 2);
        sep.push_str(&dashes);
        sep.push('|');
    }
    sep.push('\n');
    sep
}

/// Locale-aware package table header line
pub(super) fn table_header(messages: &'static Messages) -> String {
    format!(
        "| {} | {} | {} | {} |\n",
        messages.col_package, messages.col_version, messages.col_license, messages.col_description,
    )
}

/// Locale-aware package table separator line
pub(super) fn table_separator(messages: &'static Messages) -> String {
    make_separator(&[
        messages.col_package,
        messages.col_version,
        messages.col_license,
        messages.col_description,
    ])
}

/// Locale-aware vulnerability table header line
pub(super) fn vuln_table_header(messages: &'static Messages) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} |\n",
        messages.col_package,
        messages.col_current_version,
        messages.col_fixed_version,
        messages.col_cvss,
        messages.col_severity,
        messages.col_vuln_id,
    )
}

/// Locale-aware vulnerability table separator line
pub(super) fn vuln_table_separator(messages: &'static Messages) -> String {
    make_separator(&[
        messages.col_package,
        messages.col_current_version,
        messages.col_fixed_version,
        messages.col_cvss,
        messages.col_severity,
        messages.col_vuln_id,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_markdown_table_cell() {
        let input = "Text with | pipe and\nnewline";
        let escaped = escape_markdown_table_cell(input);
        assert_eq!(escaped, "Text with \\| pipe and newline");
    }
}
