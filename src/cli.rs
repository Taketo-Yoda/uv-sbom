use clap::Parser;

use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
use crate::ports::outbound::SbomFormatter;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
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

impl OutputFormat {
    /// Creates a formatter instance for the specified output format
    ///
    /// # Returns
    /// A boxed SbomFormatter trait object appropriate for this format
    pub fn create_formatter(&self) -> Box<dyn SbomFormatter> {
        match self {
            OutputFormat::Json => Box::new(CycloneDxFormatter::new()),
            OutputFormat::Markdown => Box::new(MarkdownFormatter::new()),
        }
    }

    /// Returns the progress message for the specified output format
    ///
    /// # Returns
    /// A static string containing the progress message to display
    pub fn progress_message(&self) -> &'static str {
        match self {
            OutputFormat::Json => "📝 Generating CycloneDX JSON format output...",
            OutputFormat::Markdown => "📝 Generating Markdown format output...",
        }
    }
}

/// Generate SBOMs for Python projects managed by uv
#[derive(Parser, Debug)]
#[command(name = "uv-sbom")]
#[command(version = "0.1.0")]
#[command(about = "Generate SBOMs for Python projects managed by uv", long_about = None)]
pub struct Args {
    /// Output format: json or markdown
    #[arg(short, long, default_value = "json")]
    pub format: OutputFormat,

    /// Path to the project directory (defaults to current directory)
    #[arg(short, long)]
    pub path: Option<String>,

    /// Output file path (if not specified, outputs to stdout)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Exclude packages matching patterns (supports wildcards: *)
    /// Can be specified multiple times: -e "pkg-a" -e "debug-*"
    #[arg(short, long = "exclude", value_name = "PATTERN")]
    pub exclude: Vec<String>,
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_output_format_from_str_json() {
        let format = OutputFormat::from_str("json").unwrap();
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn test_output_format_from_str_json_case_insensitive() {
        let format = OutputFormat::from_str("JSON").unwrap();
        assert!(matches!(format, OutputFormat::Json));

        let format = OutputFormat::from_str("Json").unwrap();
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn test_output_format_from_str_markdown() {
        let format = OutputFormat::from_str("markdown").unwrap();
        assert!(matches!(format, OutputFormat::Markdown));
    }

    #[test]
    fn test_output_format_from_str_md() {
        let format = OutputFormat::from_str("md").unwrap();
        assert!(matches!(format, OutputFormat::Markdown));
    }

    #[test]
    fn test_output_format_from_str_markdown_case_insensitive() {
        let format = OutputFormat::from_str("MARKDOWN").unwrap();
        assert!(matches!(format, OutputFormat::Markdown));

        let format = OutputFormat::from_str("MD").unwrap();
        assert!(matches!(format, OutputFormat::Markdown));
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
}
