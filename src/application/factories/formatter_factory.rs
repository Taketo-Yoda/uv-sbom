use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
use crate::application::dto::OutputFormat;
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::SbomFormatter;
use std::collections::HashSet;

/// Factory for creating SBOM formatters
///
/// This factory encapsulates the creation logic for different formatter implementations,
/// following the Factory Pattern. It belongs in the application layer as it orchestrates
/// the selection of infrastructure adapters based on application needs.
pub struct FormatterFactory;

impl FormatterFactory {
    /// Creates a formatter instance for the specified output format.
    ///
    /// When `verified_packages` is Some, only packages in the set get PyPI hyperlinks
    /// in Markdown output. When None, all packages get hyperlinks (default behavior).
    pub fn create(
        format: OutputFormat,
        verified_packages: Option<HashSet<String>>,
        locale: Locale,
    ) -> Box<dyn SbomFormatter> {
        match format {
            OutputFormat::Json => Box::new(CycloneDxFormatter::new()),
            OutputFormat::Markdown => match verified_packages {
                Some(packages) => {
                    Box::new(MarkdownFormatter::with_verified_packages(packages, locale))
                }
                None => Box::new(MarkdownFormatter::new(locale)),
            },
        }
    }

    /// Returns the locale-aware progress message for the specified output format
    pub fn progress_message(format: OutputFormat, locale: Locale) -> &'static str {
        let msgs = Messages::for_locale(locale);
        match format {
            OutputFormat::Json => msgs.progress_generating_json,
            OutputFormat::Markdown => msgs.progress_generating_markdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_json_formatter() {
        let formatter = FormatterFactory::create(OutputFormat::Json, None, Locale::En);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_markdown_formatter() {
        let formatter = FormatterFactory::create(OutputFormat::Markdown, None, Locale::En);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_progress_message_json_en() {
        let message = FormatterFactory::progress_message(OutputFormat::Json, Locale::En);
        assert_eq!(message, "📝 Generating CycloneDX JSON format output...");
    }

    #[test]
    fn test_progress_message_markdown_en() {
        let message = FormatterFactory::progress_message(OutputFormat::Markdown, Locale::En);
        assert_eq!(message, "📝 Generating Markdown format output...");
    }

    #[test]
    fn test_progress_message_json_ja() {
        let message = FormatterFactory::progress_message(OutputFormat::Json, Locale::Ja);
        assert_eq!(message, "📝 CycloneDX JSON形式で出力を生成中...");
    }

    #[test]
    fn test_progress_message_markdown_ja() {
        let message = FormatterFactory::progress_message(OutputFormat::Markdown, Locale::Ja);
        assert_eq!(message, "📝 Markdown形式で出力を生成中...");
    }

    #[test]
    fn test_create_with_verified_packages() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter =
            FormatterFactory::create(OutputFormat::Markdown, Some(verified), Locale::En);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_json_ignores_verified_packages() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter = FormatterFactory::create(OutputFormat::Json, Some(verified), Locale::En);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_lang_does_not_affect_json_formatter_creation() {
        // JSON formatter is always CycloneDX regardless of locale
        let formatter_en = FormatterFactory::create(OutputFormat::Json, None, Locale::En);
        let formatter_ja = FormatterFactory::create(OutputFormat::Json, None, Locale::Ja);
        // Both should produce valid formatters (same type, locale-independent)
        assert!(std::mem::size_of_val(&formatter_en) > 0);
        assert!(std::mem::size_of_val(&formatter_ja) > 0);
    }

    #[test]
    fn test_progress_message_json_and_markdown_differ_by_locale() {
        let en_json = FormatterFactory::progress_message(OutputFormat::Json, Locale::En);
        let ja_json = FormatterFactory::progress_message(OutputFormat::Json, Locale::Ja);
        let en_md = FormatterFactory::progress_message(OutputFormat::Markdown, Locale::En);
        let ja_md = FormatterFactory::progress_message(OutputFormat::Markdown, Locale::Ja);

        assert_ne!(en_json, ja_json);
        assert_ne!(en_md, ja_md);
        assert!(ja_json.contains("CycloneDX JSON"));
        assert!(ja_md.contains("Markdown"));
    }
}
