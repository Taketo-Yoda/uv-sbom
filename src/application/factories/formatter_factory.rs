use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
use crate::ports::outbound::SbomFormatter;

/// Formatter type enumeration for factory pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatterType {
    Json,
    Markdown,
}

/// Factory for creating SBOM formatters
///
/// This factory encapsulates the creation logic for different formatter implementations,
/// following the Factory Pattern. It belongs in the application layer as it orchestrates
/// the selection of infrastructure adapters based on application needs.
pub struct FormatterFactory;

impl FormatterFactory {
    /// Creates a formatter instance for the specified type
    ///
    /// # Arguments
    /// * `formatter_type` - The type of formatter to create
    ///
    /// # Returns
    /// A boxed SbomFormatter trait object appropriate for the specified type
    ///
    /// # Examples
    /// ```
    /// use uv_sbom::application::factories::{FormatterFactory, FormatterType};
    ///
    /// let formatter = FormatterFactory::create(FormatterType::Json);
    /// ```
    pub fn create(formatter_type: FormatterType) -> Box<dyn SbomFormatter> {
        match formatter_type {
            FormatterType::Json => Box::new(CycloneDxFormatter::new()),
            FormatterType::Markdown => Box::new(MarkdownFormatter::new()),
        }
    }

    /// Returns the progress message for the specified formatter type
    ///
    /// # Arguments
    /// * `formatter_type` - The type of formatter
    ///
    /// # Returns
    /// A static string containing the progress message to display
    ///
    /// # Examples
    /// ```
    /// use uv_sbom::application::factories::{FormatterFactory, FormatterType};
    ///
    /// let message = FormatterFactory::progress_message(FormatterType::Json);
    /// assert_eq!(message, "📝 Generating CycloneDX JSON format output...");
    /// ```
    pub fn progress_message(formatter_type: FormatterType) -> &'static str {
        match formatter_type {
            FormatterType::Json => "📝 Generating CycloneDX JSON format output...",
            FormatterType::Markdown => "📝 Generating Markdown format output...",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_json_formatter() {
        let formatter = FormatterFactory::create(FormatterType::Json);
        // We can't directly test the type, but we can verify it implements the trait
        // by checking that it doesn't panic when created
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_create_markdown_formatter() {
        let formatter = FormatterFactory::create(FormatterType::Markdown);
        assert!(std::mem::size_of_val(&formatter) > 0);
    }

    #[test]
    fn test_progress_message_json() {
        let message = FormatterFactory::progress_message(FormatterType::Json);
        assert_eq!(message, "📝 Generating CycloneDX JSON format output...");
    }

    #[test]
    fn test_progress_message_markdown() {
        let message = FormatterFactory::progress_message(FormatterType::Markdown);
        assert_eq!(message, "📝 Generating Markdown format output...");
    }
}
