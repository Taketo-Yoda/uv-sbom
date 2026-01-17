use clap::Parser;

use crate::application::dto::OutputFormat;
use crate::sbom_generation::domain::vulnerability::Severity;

/// Generate SBOMs for Python projects managed by uv
#[derive(Parser, Debug)]
#[command(name = "uv-sbom")]
#[command(version)]
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

    /// Validate configuration without performing network operations or generating output
    #[arg(long)]
    pub dry_run: bool,

    /// Check for known vulnerabilities using OSV API (Markdown format only)
    /// Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0
    #[arg(long)]
    pub check_cve: bool,

    /// Severity threshold for vulnerability check (low/medium/high/critical)
    #[arg(long, value_parser = parse_severity_threshold, group = "threshold")]
    pub severity_threshold: Option<Severity>,

    /// CVSS threshold for vulnerability check (0.0-10.0)
    #[arg(long, value_parser = parse_cvss_threshold, group = "threshold")]
    pub cvss_threshold: Option<f32>,
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

fn parse_severity_threshold(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!(
            "Invalid severity: {}. Valid values: low, medium, high, critical",
            s
        )),
    }
}

fn parse_cvss_threshold(s: &str) -> Result<f32, String> {
    let threshold: f32 = s
        .parse()
        .map_err(|_| "CVSS threshold must be a number".to_string())?;

    if !(0.0..=10.0).contains(&threshold) {
        return Err("CVSS threshold must be between 0.0 and 10.0".to_string());
    }
    Ok(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity_threshold_valid() {
        assert_eq!(parse_severity_threshold("low").unwrap(), Severity::Low);
        assert_eq!(
            parse_severity_threshold("medium").unwrap(),
            Severity::Medium
        );
        assert_eq!(parse_severity_threshold("high").unwrap(), Severity::High);
        assert_eq!(
            parse_severity_threshold("critical").unwrap(),
            Severity::Critical
        );
    }

    #[test]
    fn test_parse_severity_threshold_case_insensitive() {
        assert_eq!(parse_severity_threshold("LOW").unwrap(), Severity::Low);
        assert_eq!(
            parse_severity_threshold("Medium").unwrap(),
            Severity::Medium
        );
        assert_eq!(parse_severity_threshold("HIGH").unwrap(), Severity::High);
        assert_eq!(
            parse_severity_threshold("CRITICAL").unwrap(),
            Severity::Critical
        );
    }

    #[test]
    fn test_parse_severity_threshold_invalid() {
        let result = parse_severity_threshold("none");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid severity"));

        let result = parse_severity_threshold("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cvss_threshold_valid() {
        assert_eq!(parse_cvss_threshold("0.0").unwrap(), 0.0);
        assert_eq!(parse_cvss_threshold("5.5").unwrap(), 5.5);
        assert_eq!(parse_cvss_threshold("10.0").unwrap(), 10.0);
        assert_eq!(parse_cvss_threshold("7").unwrap(), 7.0);
    }

    #[test]
    fn test_parse_cvss_threshold_invalid_range() {
        let result = parse_cvss_threshold("-1.0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("between 0.0 and 10.0"));

        let result = parse_cvss_threshold("11.0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("between 0.0 and 10.0"));
    }

    #[test]
    fn test_parse_cvss_threshold_invalid_format() {
        let result = parse_cvss_threshold("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be a number"));
    }
}
