use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
use crate::application::dto::OutputFormat;
use crate::ports::outbound::SbomFormatter;

/// Factory for creating SBOM formatters
///
/// This factory encapsulates the creation logic for different formatter implementations,
/// following the Factory Pattern. It belongs in the application layer as it orchestrates
/// the selection of infrastructure adapters based on application needs.
pub struct FormatterFactory;

impl FormatterFactory {
    /// Creates a formatter instance for the specified output format
    ///
    /// # Arguments
    /// * `format` - The output format to create a formatter for
    ///
    /// # Returns
    /// A boxed SbomFormatter trait object appropriate for the specified format
    ///
    /// # Examples
    /// ```
    /// use uv_sbom::application::dto::OutputFormat;
    /// use uv_sbom::application::factories::FormatterFactory;
    ///
    /// let formatter = FormatterFactory::create(OutputFormat::Json);
    /// ```
    pub fn create(format: OutputFormat) -> Box<dyn SbomFormatter> {
        match format {
            OutputFormat::Json => Box::new(CycloneDxFormatter::new()),
            OutputFormat::Markdown => Box::new(MarkdownFormatter::new()),
        }
    }

    /// Returns the progress message for the specified output format
    ///
    /// # Arguments
    /// * `format` - The output format
    ///
    /// # Returns
    /// A static string containing the progress message to display
    ///
    /// # Examples
    /// ```
    /// use uv_sbom::application::dto::OutputFormat;
    /// use uv_sbom::application::factories::FormatterFactory;
    ///
    /// let message = FormatterFactory::progress_message(OutputFormat::Json);
    /// assert_eq!(message, "📝 Generating CycloneDX JSON format output...");
    /// ```
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
        let formatter = FormatterFactory::create(OutputFormat::Json);
        // We can't directly test the type, but we can verify it implements the trait
        // by checking that it doesn't panic when created
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_markdown_formatter() {
        let formatter = FormatterFactory::create(OutputFormat::Markdown);
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
}
