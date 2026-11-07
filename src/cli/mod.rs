pub mod config_resolver;
pub mod error_display;
pub mod exclude_groups;
pub mod incident;
pub mod runner;
pub mod workspace_summary;

use clap::Parser;

use crate::application::dto::OutputFormat;
use crate::i18n::Locale;
use crate::sbom_generation::domain::vulnerability::Severity;

/// Generate SBOMs for Python projects managed by uv
#[derive(Parser, Debug)]
#[command(name = "uv-sbom")]
#[command(version)]
#[command(about = "Generate SBOMs for Python projects managed by uv", long_about = None)]
pub struct Args {
    /// Output format: json or markdown (default: json; markdown in --incident mode)
    // No clap default, so an explicit `--format json` is distinguishable from no
    // flag: normal mode resolves CLI > config > json, and incident mode uses the
    // CLI value or markdown without reading the config file's `format` (#968).
    // A plain comment, not `///`, so clap does not print it in `--help`.
    #[arg(short, long)]
    pub format: Option<OutputFormat>,

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

    /// Disable CVE vulnerability checking (enabled by default)
    /// Vulnerability data provided by OSV (https://osv.dev) under CC-BY 4.0
    #[arg(long)]
    pub no_check_cve: bool,

    /// Severity threshold for vulnerability check (low/medium/high/critical)
    #[arg(long, value_parser = parse_severity_threshold, group = "threshold", conflicts_with = "no_check_cve")]
    pub severity_threshold: Option<Severity>,

    /// CVSS threshold for vulnerability check (0.0-10.0)
    #[arg(long, value_parser = parse_cvss_threshold, group = "threshold", conflicts_with = "no_check_cve")]
    pub cvss_threshold: Option<f32>,

    /// Suggest upgrade paths for vulnerable transitive dependencies
    #[arg(long, conflicts_with = "no_check_cve")]
    pub suggest_fix: bool,

    /// Verify PyPI links exist before generating hyperlinks (requires network access, Markdown format only)
    #[arg(long)]
    pub verify_links: bool,

    /// Explicit config file path (overrides auto-discovery)
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    pub config: Option<String>,

    /// CVE IDs to ignore (can be specified multiple times)
    #[arg(short = 'i', long = "ignore-cve", value_name = "CVE_ID")]
    pub ignore_cve: Vec<String>,

    /// Check license compliance against a policy (Markdown format only)
    #[arg(long)]
    pub check_license: bool,

    /// Check for abandoned/unmaintained packages (no upstream release within threshold days)
    #[arg(long)]
    pub check_abandoned: bool,

    /// Inactivity threshold in days for abandoned-package detection (default: 730)
    #[arg(long, value_name = "DAYS", requires = "check_abandoned")]
    pub abandoned_threshold_days: Option<u64>,

    /// Check for packages sourced from non-PyPI origins (git, path, url, private registries)
    #[arg(long)]
    pub check_non_pypi: bool,

    /// Enrich CVE results with EPSS scores and CISA KEV status (requires CVE checking)
    #[arg(long, conflicts_with = "no_check_cve")]
    pub check_exploitability: bool,

    /// Allowed license patterns (comma-separated, requires --check-license)
    /// Supports wildcards: "MIT,Apache-2.0,BSD-*"
    #[arg(long, value_delimiter = ',', requires = "check_license")]
    pub license_allow: Vec<String>,

    /// Denied license patterns (comma-separated, requires --check-license)
    /// Supports wildcards: "GPL-*,AGPL-*"
    #[arg(long, value_delimiter = ',', requires = "check_license")]
    pub license_deny: Vec<String>,

    /// Generate a uv-sbom.config.yml template file
    #[arg(long)]
    pub init: bool,

    /// Analyze all workspace members (requires a uv workspace root with [manifest] in uv.lock)
    #[arg(long, conflicts_with = "output")]
    pub workspace: bool,

    /// Compare current uv.lock against a base (git ref, tag, commit SHA, or path to a uv.lock file)
    #[arg(long, value_name = "REF_OR_PATH", conflicts_with_all = ["workspace", "init"])]
    pub diff: Option<String>,

    /// Output language for human-readable formats: en (default) or ja
    #[arg(long, default_value = "en", value_parser = parse_lang)]
    pub lang: Locale,

    /// Exclude packages reachable only through the specified dependency groups (comma-separated).
    /// Example: --exclude-groups dev,test,lint
    #[arg(long, value_delimiter = ',')]
    pub exclude_groups: Vec<String>,

    /// Exclude all non-default dependency groups (production-only mode).
    /// Equivalent to --exclude-groups <all-groups>.
    #[arg(long, conflicts_with = "exclude_groups")]
    pub production_only: bool,

    /// Target Python version for compatibility checking (PEP 440 format, e.g. 3.13)
    #[arg(long, value_name = "VERSION")]
    pub target_python: Option<String>,

    /// Trace the dependency path(s) from direct dependencies to the given package
    /// (Markdown format only)
    ///
    /// Intentionally has no config-file key: this is a one-off diagnostic query,
    /// not a persistent policy setting (see Issue #767).
    #[arg(long, value_name = "PACKAGE_NAME", conflicts_with = "workspace")]
    pub explain: Option<String>,

    /// Path to a vulnerability baseline file for suppressing previously-accepted findings
    #[arg(long, value_name = "PATH", conflicts_with = "no_check_cve")]
    pub baseline: Option<String>,

    /// Update the baseline file with all current vulnerability findings after SBOM generation
    #[arg(long, requires = "baseline")]
    pub update_baseline: bool,

    /// Render an ASCII tree visualization of the direct→transitive dependency
    /// structure (Markdown format only)
    ///
    /// Intentionally has no config-file key: this is a one-off visualization
    /// request, not a persistent policy setting (same rationale as `--explain`,
    /// see Issue #767).
    #[arg(long)]
    pub show_dependency_tree: bool,

    /// Maximum depth for the dependency tree visualization (default: 3)
    #[arg(long, value_name = "DEPTH", requires = "show_dependency_tree")]
    pub dependency_tree_depth: Option<u32>,

    /// Incident response: check whether one advisory (GHSA-, PYSEC-, CVE-, OSV- or
    /// MAL- ID) affects this project, whether the fix is released, and which
    /// command to run. For an advisory not yet in OSV, pass a quoted package
    /// range instead, e.g. "foo<2.3.2" or "foo>=2.0,<2.3.2" (operators >=, <,
    /// <= only; the quotes are needed because < is a shell redirection).
    /// Outputs Markdown unless --format is given. With --workspace, evaluates
    /// every workspace member and prints one combined report. The config
    /// file's `format` and vulnerability/license/maintenance check keys are
    /// ignored in this mode.
    //
    // Developer notes (plain comments, so clap does not print them in `--help`):
    // - The value is parsed after `--lang` is known (by
    //   `cli::incident::parse_incident_target` in `main`), not by a clap value
    //   parser, so that a malformed value is reported in the user's language
    //   (#963, #832).
    // - Intentionally has no config-file key: this is a one-off incident query,
    //   not a persistent policy setting (same rationale as `--explain`, see
    //   Issue #767).
    #[arg(
        long,
        value_name = "ID_OR_RANGE",
        conflicts_with_all = INCIDENT_CONFLICTS,
    )]
    pub incident: Option<String>,
}

/// Flags rejected together with `--incident`: other modes, and checks or
/// filters that do not apply to a single-advisory report. `--workspace` is
/// allowed (#969); it still rejects `--output` on its own.
const INCIDENT_CONFLICTS: [&str; 18] = [
    "diff",
    "init",
    "dry_run",
    "explain",
    "show_dependency_tree",
    "no_check_cve",
    "baseline",
    "update_baseline",
    "suggest_fix",
    "check_license",
    "check_abandoned",
    "check_non_pypi",
    "check_exploitability",
    "target_python",
    "severity_threshold",
    "cvss_threshold",
    "ignore_cve",
    "verify_links",
];

/// Default depth limit for `--show-dependency-tree` when `--dependency-tree-depth`
/// is not explicitly provided.
pub const DEFAULT_DEPENDENCY_TREE_DEPTH: u32 = 3;

fn parse_lang(s: &str) -> Result<Locale, String> {
    Locale::from_str(s)
        .ok_or_else(|| format!("Invalid language: '{}'. Supported languages: en, ja", s))
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
    fn test_parse_lang_valid() {
        assert_eq!(parse_lang("en").unwrap(), Locale::En);
        assert_eq!(parse_lang("ja").unwrap(), Locale::Ja);
    }

    #[test]
    fn test_parse_lang_invalid() {
        let result = parse_lang("fr");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid language: 'fr'. Supported languages: en, ja"));

        let result = parse_lang("EN");
        assert!(result.is_err());

        let result = parse_lang("");
        assert!(result.is_err());
    }

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

    #[test]
    fn test_target_python_flag_parses() {
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.13"]);
        assert_eq!(args.target_python.as_deref(), Some("3.13"));
    }

    #[test]
    fn test_target_python_flag_absent_by_default() {
        let args = Args::parse_from(["uv-sbom"]);
        assert!(args.target_python.is_none());
    }

    #[test]
    fn test_explain_flag_parses() {
        let args = Args::parse_from(["uv-sbom", "--explain", "requests"]);
        assert_eq!(args.explain.as_deref(), Some("requests"));
    }

    #[test]
    fn test_explain_flag_absent_by_default() {
        let args = Args::parse_from(["uv-sbom"]);
        assert!(args.explain.is_none());
    }

    #[test]
    fn test_explain_conflicts_with_workspace() {
        use clap::error::ErrorKind;

        let result = Args::try_parse_from(["uv-sbom", "--explain", "requests", "--workspace"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_explain_allowed_with_format_markdown() {
        let result =
            Args::try_parse_from(["uv-sbom", "--format", "markdown", "--explain", "requests"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_dependency_tree_flag_absent_by_default() {
        let args = Args::parse_from(["uv-sbom"]);
        assert!(!args.show_dependency_tree);
        assert!(args.dependency_tree_depth.is_none());
    }

    #[test]
    fn test_show_dependency_tree_flag_parses() {
        let args = Args::parse_from(["uv-sbom", "--show-dependency-tree"]);
        assert!(args.show_dependency_tree);
    }

    #[test]
    fn test_dependency_tree_depth_parses_with_show_dependency_tree() {
        let args = Args::parse_from([
            "uv-sbom",
            "--show-dependency-tree",
            "--dependency-tree-depth",
            "5",
        ]);
        assert!(args.show_dependency_tree);
        assert_eq!(args.dependency_tree_depth, Some(5));
    }

    #[test]
    fn test_dependency_tree_depth_requires_show_dependency_tree() {
        use clap::error::ErrorKind;

        let result = Args::try_parse_from(["uv-sbom", "--dependency-tree-depth", "5"]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_format_absent_by_default() {
        let args = Args::parse_from(["uv-sbom"]);
        assert!(args.format.is_none());
    }

    #[test]
    fn test_format_explicit_json_is_some() {
        let args = Args::parse_from(["uv-sbom", "--format", "json"]);
        assert_eq!(args.format, Some(OutputFormat::Json));
    }

    #[test]
    fn test_incident_flag_keeps_raw_value() {
        // Classification and validation happen in `cli::incident`, after the
        // locale is known.
        let args = Args::parse_from(["uv-sbom", "--incident", "requests>=2.0,<2.31.0"]);
        assert_eq!(args.incident.as_deref(), Some("requests>=2.0,<2.31.0"));
    }

    #[test]
    fn test_incident_conflicts_with_each_listed_flag() {
        use clap::error::ErrorKind;

        let cases: [&[&str]; 18] = [
            &["--diff", "HEAD"],
            &["--init"],
            &["--dry-run"],
            &["--explain", "requests"],
            &["--show-dependency-tree"],
            &["--no-check-cve"],
            &["--baseline", "baseline.json"],
            &["--baseline", "baseline.json", "--update-baseline"],
            &["--suggest-fix"],
            &["--check-license"],
            &["--check-abandoned"],
            &["--check-non-pypi"],
            &["--check-exploitability"],
            &["--target-python", "3.13"],
            &["--severity-threshold", "high"],
            &["--cvss-threshold", "7.0"],
            &["--ignore-cve", "CVE-2024-1"],
            &["--verify-links"],
        ];
        assert_eq!(cases.len(), INCIDENT_CONFLICTS.len());
        for extra in cases {
            let mut argv = vec!["uv-sbom", "--incident", "CVE-2023-32681"];
            argv.extend_from_slice(extra);
            let result = Args::try_parse_from(&argv);
            assert_eq!(
                result.unwrap_err().kind(),
                ErrorKind::ArgumentConflict,
                "expected a conflict for {extra:?}"
            );
        }
    }

    #[test]
    fn test_incident_accepts_scope_and_output_flags() {
        let result = Args::try_parse_from([
            "uv-sbom",
            "--incident",
            "CVE-2023-32681",
            "-p",
            "examples/sample-project",
            "-o",
            "report.md",
            "-e",
            "internal-*",
            "--exclude-groups",
            "dev",
            "--lang",
            "ja",
            "--format",
            "json",
            "-c",
            "uv-sbom.config.yml",
        ]);
        assert!(result.is_ok(), "{:?}", result.err());

        let result = Args::try_parse_from([
            "uv-sbom",
            "--incident",
            "CVE-2023-32681",
            "--production-only",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_incident_accepts_workspace_but_not_with_output() {
        use clap::error::ErrorKind;

        let args = Args::try_parse_from([
            "uv-sbom",
            "--incident",
            "CVE-2023-32681",
            "--workspace",
            "--production-only",
        ])
        .unwrap();
        assert!(args.workspace);
        assert_eq!(args.incident.as_deref(), Some("CVE-2023-32681"));

        let result = Args::try_parse_from([
            "uv-sbom",
            "--incident",
            "CVE-2023-32681",
            "--workspace",
            "-o",
            "report.md",
        ]);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::ArgumentConflict);
    }
}
