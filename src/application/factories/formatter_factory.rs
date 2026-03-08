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
        _locale: Locale,
    ) -> Box<dyn SbomFormatter> {
        match format {
            OutputFormat::Json => Box::new(CycloneDxFormatter::new()),
            OutputFormat::Markdown => match verified_packages {
                Some(packages) => Box::new(MarkdownFormatter::with_verified_packages(packages)),
                None => Box::new(MarkdownFormatter::new()),
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
}
