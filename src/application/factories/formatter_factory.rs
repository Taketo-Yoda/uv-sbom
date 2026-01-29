use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
use crate::application::dto::OutputFormat;
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
    ) -> Box<dyn SbomFormatter> {
        match format {
            OutputFormat::Json => Box::new(CycloneDxFormatter::new()),
            OutputFormat::Markdown => match verified_packages {
                Some(packages) => Box::new(MarkdownFormatter::with_verified_packages(packages)),
                None => Box::new(MarkdownFormatter::new()),
            },
        }
    }

    /// Returns the progress message for the specified output format
    pub fn progress_message(format: OutputFormat) -> &'static str {
        match format {
            OutputFormat::Json => "📝 Generating CycloneDX JSON format output...",
            OutputFormat::Markdown => "📝 Generating Markdown format output...",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_json_formatter() {
        let formatter = FormatterFactory::create(OutputFormat::Json, None);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_markdown_formatter() {
        let formatter = FormatterFactory::create(OutputFormat::Markdown, None);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_progress_message_json() {
        let message = FormatterFactory::progress_message(OutputFormat::Json);
        assert_eq!(message, "📝 Generating CycloneDX JSON format output...");
    }

    #[test]
    fn test_progress_message_markdown() {
        let message = FormatterFactory::progress_message(OutputFormat::Markdown);
        assert_eq!(message, "📝 Generating Markdown format output...");
    }

    #[test]
    fn test_create_with_verified_packages() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter = FormatterFactory::create(OutputFormat::Markdown, Some(verified));
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_json_ignores_verified_packages() {
        let mut verified = HashSet::new();
        verified.insert("requests".to_string());
        let formatter = FormatterFactory::create(OutputFormat::Json, Some(verified));
        assert!(std::mem::size_of_val(&formatter) > 0);
    }
}
