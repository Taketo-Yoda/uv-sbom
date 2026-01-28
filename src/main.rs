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
use shared::error::ExitCode;
use shared::security::validate_directory_path;
use shared::Result;
use std::path::PathBuf;
use std::process;

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

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Create adapters (Dependency Injection)
    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let pypi_repository = PyPiLicenseRepository::new()?;
    let license_repository = CachingPyPiLicenseRepository::new(pypi_repository);
    let progress_reporter = StderrProgressReporter::new();

    // Create vulnerability repository if CVE check is requested
    let vulnerability_repository = if args.check_cve {
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
    let include_dependency_info = matches!(args.format, OutputFormat::Markdown);
    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(include_dependency_info)
        .exclude_patterns(args.exclude)
        .dry_run(args.dry_run)
        .check_cve(args.check_cve)
        .severity_threshold_opt(args.severity_threshold)
        .cvss_threshold_opt(args.cvss_threshold)
        .build()?;

    // Execute use case
    let response = use_case.execute(request).await?;

    // Skip output generation for dry-run mode
    if args.dry_run {
        return Ok(false);
    }

    // Display progress message
    eprintln!("{}", FormatterFactory::progress_message(args.format));

    // Create formatter using factory
    let formatter = FormatterFactory::create(args.format);

    // Build read model and format
    let read_model = SbomReadModelBuilder::build(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
    );
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
}
