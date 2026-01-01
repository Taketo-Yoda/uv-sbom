mod cli;
mod cyclonedx;
mod error;
mod license;
mod lockfile;
mod markdown;

use anyhow::{Context, Result};
use cli::{Args, OutputFormat};
use error::SbomError;
use std::fs;
use std::io::{self, Write};
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
    let args = Args::parse_args();

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Build uv.lock file path
    let lockfile_path = project_path.join("uv.lock");

    // Check if uv.lock file exists
    if !lockfile_path.exists() {
        return Err(SbomError::LockfileNotFound {
            path: lockfile_path.clone(),
            suggestion: format!(
                "uv.lock file does not exist in project directory \"{}\".\n   \
                 Please run in the root directory of a uv project, or specify the correct path with the --path option.",
                project_path.display()
            ),
        }
        .into());
    }

    // Load and parse uv.lock file
    eprintln!("📖 Loading uv.lock file: {}", lockfile_path.display());
    let lockfile_content = fs::read_to_string(&lockfile_path).map_err(|e| {
        SbomError::LockfileParseError {
            path: lockfile_path.clone(),
            details: e.to_string(),
        }
    })?;

    let packages = lockfile::parse_lockfile(&lockfile_content).map_err(|e| {
        SbomError::LockfileParseError {
            path: lockfile_path.clone(),
            details: e.to_string(),
        }
    })?;

    eprintln!("✅ Detected {} package(s)", packages.len());

    // Fetch license information
    eprintln!("🔍 Fetching license information...");
    let packages_with_licenses = license::fetch_licenses(packages)?;

    // Generate output according to format
    let format_name = match args.format {
        OutputFormat::Json => "CycloneDX JSON",
        OutputFormat::Markdown => "Markdown",
    };
    eprintln!("📝 Generating {} format output...", format_name);

    let output_content = match args.format {
        OutputFormat::Json => {
            let bom = cyclonedx::generate_bom(packages_with_licenses)
                .context("Failed to generate CycloneDX BOM")?;
            serde_json::to_string_pretty(&bom).context("Failed to serialize JSON")?
        }
        OutputFormat::Markdown => markdown::generate_table(packages_with_licenses),
    };

    // Determine output destination
    if let Some(output_path) = args.output {
        let output_pathbuf = PathBuf::from(&output_path);

        // Check if output directory exists
        if let Some(parent) = output_pathbuf.parent() {
            if !parent.exists() && parent != Path::new("") {
                return Err(SbomError::FileWriteError {
                    path: output_pathbuf.clone(),
                    details: format!(
                        "Parent directory does not exist: {}",
                        parent.display()
                    ),
                }
                .into());
            }
        }

        fs::write(&output_pathbuf, output_content).map_err(|e| SbomError::FileWriteError {
            path: output_pathbuf.clone(),
            details: e.to_string(),
        })?;
        eprintln!("✅ Output complete: {}", output_pathbuf.display());
    } else {
        io::stdout()
            .write_all(output_content.as_bytes())
            .context("Failed to write to stdout")?;
    }

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

    if !path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Not a directory".to_string(),
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
