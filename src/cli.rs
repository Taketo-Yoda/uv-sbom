use clap::Parser;

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
                "無効なフォーマット: {}。'json'または'markdown'を指定してください",
                s
            )),
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
}

impl Args {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
