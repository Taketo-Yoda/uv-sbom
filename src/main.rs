mod adapters;
mod application;
mod cli;
mod ports;
mod sbom_generation;
mod shared;

use adapters::outbound::console::StderrProgressReporter;
use adapters::outbound::filesystem::FileSystemReader;
use adapters::outbound::network::{CachingPyPiLicenseRepository, OsvClient, PyPiLicenseRepository};
use application::dto::{OutputFormat, SbomRequest};
use application::factories::{FormatterFactory, PresenterFactory, PresenterType};
use application::read_models::SbomReadModelBuilder;
use application::use_cases::GenerateSbomUseCase;
use clap::Parser;
use cli::Args;
use owo_colors::OwoColorize;
use sbom_generation::domain::vulnerability::Severity;
use shared::error::ExitCode;
use shared::security::validate_directory_path;
use shared::Result;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process;
use uv_sbom::config::{self, ConfigFile, IgnoreCve};

#[tokio::main]
async fn main() {
    // Parse command-line arguments first to catch argument errors early
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            // Print the error message (clap formats these nicely)
            let _ = e.print();

            // Use exit code 0 for help/version, exit code 2 for actual argument errors
            let exit_code = if e.use_stderr() {
                ExitCode::InvalidArguments
            } else {
                ExitCode::Success
            };
            process::exit(exit_code.as_i32());
        }
    };

    // Run the main application logic
    match run(args).await {
        Ok(has_vulnerabilities) => {
            if has_vulnerabilities {
                process::exit(ExitCode::VulnerabilitiesDetected.as_i32());
            }
            process::exit(ExitCode::Success.as_i32());
        }
        Err(e) => {
            eprintln!("\n❌ An error occurred:\n");
            eprintln!("{}", e);

            // Display error chain
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("\nCaused by: {}", err);
                source = err.source();
            }

            eprintln!();
            process::exit(ExitCode::ApplicationError.as_i32());
        }
    }
}

/// Runs the main application logic.
///
/// Returns `Ok(true)` if vulnerabilities were detected above threshold,
/// `Ok(false)` if no vulnerabilities (or all below threshold),
/// or `Err` for application errors.
async fn run(args: Args) -> Result<bool> {
    // Display startup banner
    display_banner();

    // Warn if check_cve is used with JSON format
    if args.check_cve && args.format == OutputFormat::Json {
        eprintln!("⚠️  Warning: --check-cve has no effect with JSON format.");
        eprintln!("   Vulnerability data is not included in JSON output.");
        eprintln!("   Use --format markdown to see vulnerability report.");
        eprintln!();
    }

    // Warn if verify_links is used with JSON format
    if args.verify_links && args.format == OutputFormat::Json {
        eprintln!("⚠️  Warning: --verify-links has no effect with JSON format.");
        eprintln!("   PyPI link verification only applies to Markdown output.");
        eprintln!("   Use --format markdown to use link verification.");
        eprintln!();
    }

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Load config file (explicit path or auto-discovery)
    let config = load_config(&args, &project_path)?;

    // Merge CLI and config values
    let merged = merge_config(&args, &config);

    // Create adapters (Dependency Injection)
    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let pypi_repository = PyPiLicenseRepository::new()?;
    let license_repository = CachingPyPiLicenseRepository::new(pypi_repository);
    let progress_reporter = StderrProgressReporter::new();

    // Create vulnerability repository if CVE check is requested
    let vulnerability_repository = if merged.check_cve {
        Some(OsvClient::new()?)
    } else {
        None
    };

    // Create use case with injected dependencies
    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        vulnerability_repository,
    );

    // Create request using builder pattern
    let include_dependency_info = matches!(merged.format, OutputFormat::Markdown);
    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(include_dependency_info)
        .exclude_patterns(merged.exclude_patterns)
        .dry_run(args.dry_run)
        .check_cve(merged.check_cve)
        .severity_threshold_opt(merged.severity_threshold)
        .cvss_threshold_opt(merged.cvss_threshold)
        .ignore_cves(merged.ignore_cves)
        .build()?;

    // Execute use case
    let response = use_case.execute(request).await?;

    // Skip output generation for dry-run mode
    if args.dry_run {
        return Ok(false);
    }

    // Display progress message
    eprintln!("{}", FormatterFactory::progress_message(merged.format));

    // Build read model first so we can extract package names for verification
    let read_model = SbomReadModelBuilder::build(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
    );

    // Verify PyPI links if requested
    let verified_packages = if args.verify_links && merged.format == OutputFormat::Markdown {
        eprintln!("🔗 Verifying PyPI links...");
        let pypi_verifier = PyPiLicenseRepository::new()?;
        let package_names: Vec<String> = read_model
            .components
            .iter()
            .map(|c| c.name.clone())
            .collect();
        Some(pypi_verifier.verify_packages(&package_names).await)
    } else {
        None
    };

    // Create formatter using factory with optional verified packages
    let formatter = FormatterFactory::create(merged.format, verified_packages);
    let formatted_output = formatter.format(&read_model)?;

    // Create presenter using factory
    let presenter_type = if let Some(output_path) = args.output {
        PresenterType::File(PathBuf::from(output_path))
    } else {
        PresenterType::Stdout
    };

    let presenter = PresenterFactory::create(presenter_type);
    presenter.present(&formatted_output)?;

    // Determine if vulnerabilities were detected above threshold
    let has_vulnerabilities = response.has_vulnerabilities_above_threshold;

    Ok(has_vulnerabilities)
}

fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        "{} {} {}",
        "🚀".bright_yellow(),
        "uv-sbom".bright_cyan().bold(),
        format!("v{}", version).bright_green()
    );
    eprintln!();
}

/// Merged configuration after combining CLI arguments and config file values.
struct MergedConfig {
    format: OutputFormat,
    exclude_patterns: Vec<String>,
    check_cve: bool,
    severity_threshold: Option<Severity>,
    cvss_threshold: Option<f32>,
    ignore_cves: Vec<IgnoreCve>,
}

/// Load a config file from an explicit path or via auto-discovery.
fn load_config(args: &Args, project_path: &std::path::Path) -> Result<Option<ConfigFile>> {
    if let Some(ref config_path) = args.config {
        let path = std::path::Path::new(config_path);
        let cfg = config::load_config_from_path(path)?;
        eprintln!("📄 Loaded config from: {}", path.display());
        Ok(Some(cfg))
    } else {
        let cfg = config::discover_config(project_path)?;
        if cfg.is_some() {
            eprintln!("📄 Auto-discovered config file in project directory.");
        }
        Ok(cfg)
    }
}

/// Merge CLI arguments with config file values.
///
/// Priority: CLI > config file > defaults.
/// List fields (exclude_patterns, ignore_cves) are merged and deduplicated.
/// Scalar fields use CLI value if present, otherwise config value, otherwise default.
fn merge_config(args: &Args, config: &Option<ConfigFile>) -> MergedConfig {
    let config = match config {
        Some(c) => c,
        None => {
            // No config file — use CLI values directly
            return MergedConfig {
                format: args.format,
                exclude_patterns: args.exclude.clone(),
                check_cve: args.check_cve,
                severity_threshold: args.severity_threshold,
                cvss_threshold: args.cvss_threshold,
                ignore_cves: args
                    .ignore_cve
                    .iter()
                    .map(|id| IgnoreCve {
                        id: id.clone(),
                        reason: None,
                    })
                    .collect(),
            };
        }
    };

    // Merge exclude_patterns: combine both sources, deduplicate
    let exclude_patterns = merge_string_lists(&args.exclude, &config.exclude_packages);

    // Merge ignore_cves: combine both sources, deduplicate by ID
    let cli_ignore_cves: Vec<IgnoreCve> = args
        .ignore_cve
        .iter()
        .map(|id| IgnoreCve {
            id: id.clone(),
            reason: None,
        })
        .collect();
    let ignore_cves = merge_ignore_cves(&cli_ignore_cves, &config.ignore_cves);

    // Format: CLI > config > default (json)
    // Note: clap always provides a default value for format, so we check if user explicitly
    // provided it by comparing against the default. However, since clap's default_value means
    // args.format is always set, we use config only when format is json (default) and config
    // provides a different value.
    let format = if let Some(ref config_format) = config.format {
        // If user didn't explicitly pass --format, use config value
        // clap default is "json", so if args.format == Json, config might override
        // But we can't distinguish "user passed --format json" from "default json"
        // Convention: CLI always wins since clap provides the value
        if args.format != OutputFormat::Json {
            args.format
        } else {
            config_format.parse::<OutputFormat>().unwrap_or(args.format)
        }
    } else {
        args.format
    };

    // check_cve: CLI flag || config value
    let check_cve = args.check_cve || config.check_cve.unwrap_or(false);

    // severity_threshold: CLI > config > None
    let severity_threshold = args.severity_threshold.or_else(|| {
        config
            .severity_threshold
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "low" => Some(Severity::Low),
                "medium" => Some(Severity::Medium),
                "high" => Some(Severity::High),
                "critical" => Some(Severity::Critical),
                _ => None,
            })
    });

    // cvss_threshold: CLI > config > None
    let cvss_threshold = args
        .cvss_threshold
        .or(config.cvss_threshold.map(|v| v as f32));

    MergedConfig {
        format,
        exclude_patterns,
        check_cve,
        severity_threshold,
        cvss_threshold,
        ignore_cves,
    }
}

/// Merge two string lists and deduplicate.
fn merge_string_lists(cli: &[String], config: &Option<Vec<String>>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // CLI values first (higher priority)
    for item in cli {
        if seen.insert(item.clone()) {
            result.push(item.clone());
        }
    }

    // Then config values
    if let Some(config_items) = config {
        for item in config_items {
            if seen.insert(item.clone()) {
                result.push(item.clone());
            }
        }
    }

    result
}

/// Merge two ignore_cves lists and deduplicate by ID (CLI entries take precedence).
fn merge_ignore_cves(cli: &[IgnoreCve], config: &Option<Vec<IgnoreCve>>) -> Vec<IgnoreCve> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // CLI values first (higher priority)
    for cve in cli {
        if seen.insert(cve.id.clone()) {
            result.push(cve.clone());
        }
    }

    // Then config values
    if let Some(config_cves) = config {
        for cve in config_cves {
            if seen.insert(cve.id.clone()) {
                result.push(cve.clone());
            }
        }
    }

    result
}

/// Validates that the project path is a valid directory.
///
/// This delegates to `validate_directory_path` in `shared::security`,
/// which provides comprehensive security validation including:
/// - Existence check
/// - Symlink rejection
/// - Directory type verification
/// - Path canonicalization for traversal prevention
fn validate_project_path(path: &std::path::Path) -> Result<()> {
    validate_directory_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_project_path_valid_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_project_path(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_project_path_nonexistent() {
        let nonexistent_path = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let result = validate_project_path(&nonexistent_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_string = format!("{}", err);
        assert!(err_string.contains("Directory does not exist"));
    }

    #[test]
    fn test_validate_project_path_file_not_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        fs::write(&file_path, "test content").unwrap();

        let result = validate_project_path(&file_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_string = format!("{}", err);
        assert!(err_string.contains("Not a directory"));
    }

    #[test]
    fn test_validate_project_path_current_directory() {
        let current_dir = std::env::current_dir().unwrap();
        let result = validate_project_path(&current_dir);
        assert!(result.is_ok());
    }

    // --- Merge logic tests ---

    #[test]
    fn test_merge_string_lists_both_empty() {
        let result = merge_string_lists(&[], &None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_string_lists_cli_only() {
        let cli = vec!["a".to_string(), "b".to_string()];
        let result = merge_string_lists(&cli, &None);
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn test_merge_string_lists_config_only() {
        let config = Some(vec!["x".to_string(), "y".to_string()]);
        let result = merge_string_lists(&[], &config);
        assert_eq!(result, vec!["x", "y"]);
    }

    #[test]
    fn test_merge_string_lists_deduplication() {
        let cli = vec!["a".to_string(), "b".to_string()];
        let config = Some(vec!["b".to_string(), "c".to_string()]);
        let result = merge_string_lists(&cli, &config);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_merge_ignore_cves_both_empty() {
        let result = merge_ignore_cves(&[], &None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_ignore_cves_cli_only() {
        let cli = vec![IgnoreCve {
            id: "CVE-2024-1".to_string(),
            reason: None,
        }];
        let result = merge_ignore_cves(&cli, &None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2024-1");
    }

    #[test]
    fn test_merge_ignore_cves_config_only() {
        let config = Some(vec![IgnoreCve {
            id: "CVE-2024-2".to_string(),
            reason: Some("reason".to_string()),
        }]);
        let result = merge_ignore_cves(&[], &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2024-2");
        assert_eq!(result[0].reason.as_deref(), Some("reason"));
    }

    #[test]
    fn test_merge_ignore_cves_deduplication_cli_wins() {
        let cli = vec![IgnoreCve {
            id: "CVE-2024-1".to_string(),
            reason: Some("cli reason".to_string()),
        }];
        let config = Some(vec![
            IgnoreCve {
                id: "CVE-2024-1".to_string(),
                reason: Some("config reason".to_string()),
            },
            IgnoreCve {
                id: "CVE-2024-2".to_string(),
                reason: None,
            },
        ]);
        let result = merge_ignore_cves(&cli, &config);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "CVE-2024-1");
        assert_eq!(result[0].reason.as_deref(), Some("cli reason"));
        assert_eq!(result[1].id, "CVE-2024-2");
    }

    #[test]
    fn test_merge_config_no_config_file() {
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None);
        assert_eq!(result.format, OutputFormat::Json);
        assert!(result.exclude_patterns.is_empty());
        assert!(!result.check_cve);
        assert!(result.severity_threshold.is_none());
        assert!(result.cvss_threshold.is_none());
        assert!(result.ignore_cves.is_empty());
    }

    #[test]
    fn test_merge_config_config_provides_defaults() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            format: Some("markdown".to_string()),
            exclude_packages: Some(vec!["pkg-a".to_string()]),
            check_cve: Some(true),
            severity_threshold: Some("high".to_string()),
            cvss_threshold: Some(7.0),
            ignore_cves: Some(vec![IgnoreCve {
                id: "CVE-2024-1".to_string(),
                reason: Some("not applicable".to_string()),
            }]),
            unknown_fields: Default::default(),
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.format, OutputFormat::Markdown);
        assert_eq!(result.exclude_patterns, vec!["pkg-a"]);
        assert!(result.check_cve);
        assert_eq!(result.severity_threshold, Some(Severity::High));
        assert_eq!(result.cvss_threshold, Some(7.0));
        assert_eq!(result.ignore_cves.len(), 1);
        assert_eq!(result.ignore_cves[0].id, "CVE-2024-1");
    }

    #[test]
    fn test_merge_config_cli_overrides_format() {
        let args = Args::parse_from(["uv-sbom", "--format", "markdown"]);
        let config = Some(ConfigFile {
            format: Some("json".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_merge_config_check_cve_cli_flag() {
        let args = Args::parse_from(["uv-sbom", "--check-cve"]);
        let config = Some(ConfigFile {
            check_cve: Some(false),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert!(result.check_cve);
    }

    #[test]
    fn test_merge_config_check_cve_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert!(result.check_cve);
    }

    #[test]
    fn test_merge_config_exclude_patterns_merged() {
        let args = Args::parse_from(["uv-sbom", "-e", "cli-pkg"]);
        let config = Some(ConfigFile {
            exclude_packages: Some(vec!["config-pkg".to_string(), "cli-pkg".to_string()]),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.exclude_patterns, vec!["cli-pkg", "config-pkg"]);
    }

    #[test]
    fn test_merge_config_ignore_cves_merged() {
        let args = Args::parse_from(["uv-sbom", "-i", "CVE-2024-1"]);
        let config = Some(ConfigFile {
            ignore_cves: Some(vec![
                IgnoreCve {
                    id: "CVE-2024-1".to_string(),
                    reason: Some("config reason".to_string()),
                },
                IgnoreCve {
                    id: "CVE-2024-2".to_string(),
                    reason: None,
                },
            ]),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.ignore_cves.len(), 2);
        // CLI entry takes precedence (no reason)
        assert_eq!(result.ignore_cves[0].id, "CVE-2024-1");
        assert!(result.ignore_cves[0].reason.is_none());
        assert_eq!(result.ignore_cves[1].id, "CVE-2024-2");
    }

    #[test]
    fn test_merge_config_severity_threshold_cli_wins() {
        let args = Args::parse_from(["uv-sbom", "--check-cve", "--severity-threshold", "critical"]);
        let config = Some(ConfigFile {
            severity_threshold: Some("low".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.severity_threshold, Some(Severity::Critical));
    }

    #[test]
    fn test_merge_config_severity_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            severity_threshold: Some("medium".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.severity_threshold, Some(Severity::Medium));
    }

    #[test]
    fn test_merge_config_cvss_threshold_cli_wins() {
        let args = Args::parse_from(["uv-sbom", "--check-cve", "--cvss-threshold", "8.5"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(5.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.cvss_threshold, Some(8.5));
    }

    #[test]
    fn test_merge_config_cvss_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(6.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.cvss_threshold, Some(6.0));
    }
}
