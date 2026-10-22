use std::borrow::Cow;

use crate::i18n::Messages;

/// Maximum characters for license text in Markdown table cells.
/// Full text is preserved in CycloneDX output; this threshold keeps
/// human-readable Markdown tables concise.
pub(crate) const LICENSE_TEXT_MAX_LEN: usize = 100;

/// Truncates `text` to at most `max_len` characters, appending "..." if truncated.
/// Returns `Cow::Borrowed` when no truncation is needed to avoid allocation.
pub(crate) fn truncate_for_table(text: &str, max_len: usize) -> Cow<'_, str> {
    if text.chars().count() <= max_len {
        Cow::Borrowed(text)
    } else {
        let truncated: String = text.chars().take(max_len).collect();
        Cow::Owned(format!("{truncated}..."))
    }
}

/// Escapes pipe characters and newlines for safe Markdown table rendering
pub(crate) fn escape_markdown_table_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// Generates a Markdown table separator row from column header strings.
/// Each separator cell width matches the header's char count plus two spaces.
pub(crate) fn make_separator(cols: &[&str]) -> String {
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

/// Locale-aware vulnerability table header with optional exploitability columns
pub(super) fn vuln_table_header_with_exploitability(
    messages: &'static Messages,
    show_exploitability: bool,
) -> String {
    if show_exploitability {
        format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            messages.col_package,
            messages.col_current_version,
            messages.col_fixed_version,
            messages.col_cvss,
            messages.col_severity,
            messages.col_vuln_id,
            messages.col_exploited_kev,
            messages.col_epss,
        )
    } else {
        vuln_table_header(messages)
    }
}

/// Locale-aware vulnerability table separator with optional exploitability columns
pub(super) fn vuln_table_separator_with_exploitability(
    messages: &'static Messages,
    show_exploitability: bool,
) -> String {
    if show_exploitability {
        make_separator(&[
            messages.col_package,
            messages.col_current_version,
            messages.col_fixed_version,
            messages.col_cvss,
            messages.col_severity,
            messages.col_vuln_id,
            messages.col_exploited_kev,
            messages.col_epss,
        ])
    } else {
        vuln_table_separator(messages)
    }
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

    #[test]
    fn test_truncate_short_text_unchanged() {
        let result = truncate_for_table("MIT", 100);
        assert_eq!(result, "MIT");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_truncate_empty_string() {
        let result = truncate_for_table("", 100);
        assert_eq!(result, "");
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_truncate_at_exact_threshold() {
        let text = "a".repeat(100);
        let result = truncate_for_table(&text, 100);
        assert_eq!(result, text);
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_truncate_one_over_threshold() {
        let text = "a".repeat(101);
        let result = truncate_for_table(&text, 100);
        let expected = format!("{}...", "a".repeat(100));
        assert_eq!(result, expected);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_truncate_long_text() {
        let text = "a".repeat(200);
        let result = truncate_for_table(&text, 100);
        assert_eq!(result.len(), 103); // 100 + "..."
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_multibyte_characters() {
        let text = "あ".repeat(101);
        let result = truncate_for_table(&text, 100);
        assert_eq!(result.chars().count(), 103); // 100 chars + "..."
        assert!(result.ends_with("..."));
    }
}
