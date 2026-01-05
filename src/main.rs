mod adapters;
mod application;
mod cli;
mod ports;
mod sbom_generation;
mod shared;

use adapters::outbound::console::StderrProgressReporter;
use adapters::outbound::filesystem::{FileSystemReader, FileSystemWriter, StdoutPresenter};
use adapters::outbound::network::PyPiLicenseRepository;
use application::dto::SbomRequest;
use application::factories::{FormatterFactory, FormatterType};
use application::use_cases::GenerateSbomUseCase;
use cli::{Args, OutputFormat};
use ports::outbound::OutputPresenter;
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
    // Parse command-line arguments
    let args = Args::parse_args();

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Create adapters (Dependency Injection)
    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = PyPiLicenseRepository::new()?;
    let progress_reporter = StderrProgressReporter::new();

    // Create use case with injected dependencies
    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    // Create request
    let include_dependency_info = matches!(args.format, OutputFormat::Markdown);
    let request = SbomRequest::new(project_path, include_dependency_info, args.exclude);

    // Execute use case
    let response = use_case.execute(request)?;

    // Convert CLI format to application layer format type
    let formatter_type = match args.format {
        OutputFormat::Json => FormatterType::Json,
        OutputFormat::Markdown => FormatterType::Markdown,
    };

    // Display progress message
    eprintln!("{}", FormatterFactory::progress_message(formatter_type));

    // Create formatter using factory
    let formatter = FormatterFactory::create(formatter_type);
    let formatted_output = if let Some(dep_graph) = response.dependency_graph.as_ref() {
        formatter.format_with_dependencies(
            dep_graph,
            response.enriched_packages,
            &response.metadata,
        )?
    } else {
        formatter.format(response.enriched_packages, &response.metadata)?
    };

    // Present output
    let presenter: Box<dyn OutputPresenter> = if let Some(output_path) = args.output {
        Box::new(FileSystemWriter::new(PathBuf::from(output_path)))
    } else {
        Box::new(StdoutPresenter::new())
    };

    presenter.present(&formatted_output)?;

    Ok(())
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
