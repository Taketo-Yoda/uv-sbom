use clap::Parser;

use crate::application::dto::OutputFormat;

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
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
