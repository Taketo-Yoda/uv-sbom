/// Output format enumeration for SBOM generation
///
/// This enum represents the supported output formats for SBOM documents.
/// It belongs in the application layer as it represents an application-level
/// concern that both the CLI (inbound adapter) and formatters (outbound adapters)
/// need to understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// CycloneDX JSON format (default)
    Json,
    /// Human-readable Markdown format
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => Err(format!(
                "Invalid format: {}. Please specify 'json' or 'markdown'",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Markdown => write!(f, "markdown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_output_format_from_str_json() {
        let format = OutputFormat::from_str("json").unwrap();
        assert_eq!(format, OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_json_case_insensitive() {
        let format = OutputFormat::from_str("JSON").unwrap();
        assert_eq!(format, OutputFormat::Json);

        let format = OutputFormat::from_str("Json").unwrap();
        assert_eq!(format, OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_markdown() {
        let format = OutputFormat::from_str("markdown").unwrap();
        assert_eq!(format, OutputFormat::Markdown);
    }

    #[test]
    fn test_output_format_from_str_md() {
        let format = OutputFormat::from_str("md").unwrap();
        assert_eq!(format, OutputFormat::Markdown);
    }

    #[test]
    fn test_output_format_from_str_markdown_case_insensitive() {
        let format = OutputFormat::from_str("MARKDOWN").unwrap();
        assert_eq!(format, OutputFormat::Markdown);

        let format = OutputFormat::from_str("MD").unwrap();
        assert_eq!(format, OutputFormat::Markdown);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = OutputFormat::from_str("invalid");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("Invalid format"));
        assert!(error.contains("invalid"));
        assert!(error.contains("json"));
        assert!(error.contains("markdown"));
    }

    #[test]
    fn test_output_format_from_str_empty() {
        let result = OutputFormat::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(OutputFormat::Json.to_string(), "json");
        assert_eq!(OutputFormat::Markdown.to_string(), "markdown");
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Json, OutputFormat::Json);
        assert_eq!(OutputFormat::Markdown, OutputFormat::Markdown);
        assert_ne!(OutputFormat::Json, OutputFormat::Markdown);
    }

    #[test]
    fn test_output_format_clone() {
        let original = OutputFormat::Json;
        let cloned = original;
        assert_eq!(original, cloned);
    }
}
