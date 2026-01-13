mod adapters;
mod application;
mod cli;
mod ports;
mod sbom_generation;
mod shared;

use adapters::outbound::console::StderrProgressReporter;
use adapters::outbound::filesystem::FileSystemReader;
use adapters::outbound::network::{OsvClient, PyPiLicenseRepository};
use application::dto::{OutputFormat, SbomRequest};
use application::factories::{FormatterFactory, PresenterFactory, PresenterType};
use application::use_cases::GenerateSbomUseCase;
use cli::Args;
use owo_colors::OwoColorize;
use shared::error::SbomError;
use shared::Result;
use std::path::{Path, PathBuf};
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("\n❌ An error occurred:\n");
        eprintln!("{}", e);

        // Display error chain
        let mut source = e.source();
        while let Some(err) = source {
            eprintln!("\nCaused by: {}", err);
            source = err.source();
        }

        eprintln!();
        process::exit(1);
    }
}

fn run() -> Result<()> {
    // Display startup banner
    display_banner();

    // Parse command-line arguments
    let args = Args::parse_args();

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
    let license_repository = PyPiLicenseRepository::new()?;
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

    // Create request
    let include_dependency_info = matches!(args.format, OutputFormat::Markdown);
    let request = SbomRequest::new(
        project_path,
        include_dependency_info,
        args.exclude,
        args.dry_run,
        args.check_cve,
    );

    // Execute use case
    let response = use_case.execute(request)?;

    // Skip output generation for dry-run mode
    if args.dry_run {
        return Ok(());
    }

    // Display progress message
    eprintln!("{}", FormatterFactory::progress_message(args.format));

    // Create formatter using factory
    let formatter = FormatterFactory::create(args.format);
    let vulnerability_report = response.vulnerability_report.as_deref();
    let formatted_output = if let Some(dep_graph) = response.dependency_graph.as_ref() {
        formatter.format_with_dependencies(
            dep_graph,
            response.enriched_packages,
            &response.metadata,
            vulnerability_report,
        )?
    } else {
        formatter.format(
            response.enriched_packages,
            &response.metadata,
            vulnerability_report,
        )?
    };

    // Create presenter using factory
    let presenter_type = if let Some(output_path) = args.output {
        PresenterType::File(PathBuf::from(output_path))
    } else {
        PresenterType::Stdout
    };

    let presenter = PresenterFactory::create(presenter_type);
    presenter.present(&formatted_output)?;

    Ok(())
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

fn validate_project_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Directory does not exist".to_string(),
        }
        .into());
    }

    // Security check: Reject symbolic links for project paths
    let metadata = std::fs::symlink_metadata(path).map_err(|e| SbomError::InvalidProjectPath {
        path: path.to_path_buf(),
        reason: format!("Failed to read path metadata: {}", e),
    })?;

    if metadata.is_symlink() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Security: Project path is a symbolic link. For security reasons, symbolic links are not allowed.".to_string(),
        }
        .into());
    }

    if !path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Not a directory".to_string(),
        }
        .into());
    }

    // Security check: Canonicalize path to prevent path traversal
    let canonical_path = path
        .canonicalize()
        .map_err(|e| SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: format!("Failed to canonicalize path: {}", e),
        })?;

    // Validate that the canonical path is actually a directory
    // (additional check after canonicalization)
    if !canonical_path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Resolved path is not a directory".to_string(),
        }
        .into());
    }

    Ok(())
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
