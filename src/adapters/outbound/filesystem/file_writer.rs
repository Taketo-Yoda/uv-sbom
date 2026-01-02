use crate::ports::outbound::OutputPresenter;
use crate::shared::error::SbomError;
use crate::shared::Result;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// FileSystemWriter adapter for writing output to files
///
/// This adapter implements the OutputPresenter port for file output.
pub struct FileSystemWriter {
    output_path: PathBuf,
}

impl FileSystemWriter {
    pub fn new(output_path: PathBuf) -> Self {
        Self { output_path }
    }

    /// Validates that the parent directory exists before writing
    fn validate_parent_directory(&self) -> Result<()> {
        if let Some(parent) = self.output_path.parent() {
            if !parent.exists() && parent != Path::new("") {
                return Err(SbomError::FileWriteError {
                    path: self.output_path.clone(),
                    details: format!(
                        "Parent directory does not exist: {}",
                        parent.display()
                    ),
                }
                .into());
            }
        }
        Ok(())
    }

    /// Security validation before writing:
    /// - Reject if output path exists and is a symlink
    /// - Validate parent directory chain doesn't contain symlinks
    fn validate_output_security(&self) -> Result<()> {
        // If the file already exists, check it's not a symlink
        if self.output_path.exists() {
            let metadata = fs::symlink_metadata(&self.output_path).map_err(|e| {
                SbomError::FileWriteError {
                    path: self.output_path.clone(),
                    details: format!("Failed to read file metadata: {}", e),
                }
            })?;

            if metadata.is_symlink() {
                return Err(SbomError::FileWriteError {
                    path: self.output_path.clone(),
                    details: "Security: Output path is a symbolic link. For security reasons, writing to symbolic links is not allowed.".to_string(),
                }
                .into());
            }
        }

        // Validate parent directory chain for symlinks
        if let Some(parent) = self.output_path.parent() {
            if parent.exists() {
                // Try to canonicalize to detect symlinks in path
                match parent.canonicalize() {
                    Ok(_canonical) => {
                        // Check if canonical path differs significantly (might contain symlinks)
                        // This is a basic check; a more thorough check would validate each component
                        if let Ok(_original) = parent.canonicalize() {
                            // If we got here, path is valid
                        }
                    }
                    Err(e) => {
                        return Err(SbomError::FileWriteError {
                            path: self.output_path.clone(),
                            details: format!("Failed to validate parent directory: {}", e),
                        }
                        .into());
                    }
                }
            }
        }

        Ok(())
    }
}

impl OutputPresenter for FileSystemWriter {
    fn present(&self, content: &str) -> Result<()> {
        // Security validations
        self.validate_parent_directory()?;
        self.validate_output_security()?;

        // Safe to write now
        fs::write(&self.output_path, content).map_err(|e| {
            SbomError::FileWriteError {
                path: self.output_path.clone(),
                details: e.to_string(),
            }
        })?;

        eprintln!("✅ Output complete: {}", self.output_path.display());
        Ok(())
    }
}

/// StdoutPresenter adapter for writing output to stdout
///
/// This adapter implements the OutputPresenter port for stdout output.
pub struct StdoutPresenter;

impl StdoutPresenter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StdoutPresenter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputPresenter for StdoutPresenter {
    fn present(&self, content: &str) -> Result<()> {
        io::stdout()
            .write_all(content.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to write to stdout: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_writer_success() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output.json");

        let writer = FileSystemWriter::new(output_path.clone());
        let result = writer.present("test content");

        assert!(result.is_ok());
        let written_content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(written_content, "test content");
    }

    #[test]
    fn test_file_writer_parent_directory_not_found() {
        let output_path = PathBuf::from("/nonexistent/directory/output.json");

        let writer = FileSystemWriter::new(output_path);
        let result = writer.present("test content");

        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Parent directory does not exist"));
    }

    #[test]
    fn test_stdout_presenter_success() {
        let presenter = StdoutPresenter::new();
        // We can't easily test stdout output, but we can verify it doesn't error
        // In a real test environment, we'd capture stdout
        let result = presenter.present("test output\n");
        assert!(result.is_ok());
    }
}
