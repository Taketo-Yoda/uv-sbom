use crate::shared::error::SbomError;
use crate::shared::Result;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

/// Maximum file size for security (100 MB)
/// This prevents DoS attacks via excessively large files
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Result of file validation containing metadata for reuse
///
/// This struct allows callers to reuse the metadata obtained during validation,
/// avoiding redundant filesystem calls.
#[derive(Debug)]
pub struct FileValidationResult {
    pub metadata: Metadata,
}

/// Validates a file path and returns metadata for reuse.
///
/// This function combines multiple validation checks into a single operation:
/// - Verifies the path is not a symbolic link
/// - Verifies the path points to a regular file
/// - Validates file size is within limits
///
/// # Arguments
/// * `path` - The path to validate
/// * `file_description` - Description of the file for error messages
/// * `max_size` - Maximum allowed file size in bytes
///
/// # Returns
/// `FileValidationResult` containing the file metadata on success
///
/// # Errors
/// Returns `SbomError::SecurityError` for symlinks or non-files
/// Returns `SbomError::FileReadError` for metadata read failures or size violations
pub fn validate_and_get_metadata(
    path: &Path,
    file_description: &str,
    max_size: u64,
) -> Result<FileValidationResult> {
    // Get metadata once and reuse it for all checks
    let metadata = fs::symlink_metadata(path).map_err(|e| SbomError::FileReadError {
        path: path.to_path_buf(),
        details: format!("Failed to read {} metadata: {}", file_description, e),
    })?;

    // Security check: Reject symbolic links
    if metadata.is_symlink() {
        return Err(SbomError::SecurityError {
            path: path.to_path_buf(),
            reason: format!("{} is a symbolic link", file_description),
            hint:
                "For security reasons, symbolic links are not allowed. Use a regular file instead."
                    .to_string(),
        }
        .into());
    }

    // Security check: Must be a regular file
    if !metadata.is_file() {
        return Err(SbomError::SecurityError {
            path: path.to_path_buf(),
            reason: format!("{} is not a regular file", file_description),
            hint: "Please specify a regular file, not a directory or special file.".to_string(),
        }
        .into());
    }

    // Security check: File size limit
    if metadata.len() > max_size {
        return Err(SbomError::FileReadError {
            path: path.to_path_buf(),
            details: format!(
                "{} is too large ({} bytes). Maximum allowed size is {} bytes",
                file_description,
                metadata.len(),
                max_size
            ),
        }
        .into());
    }

    Ok(FileValidationResult { metadata })
}

/// Reads a file with comprehensive security checks.
///
/// This function provides:
/// - Symlink rejection
/// - File type validation
/// - File size limits
/// - TOCTOU mitigation by verifying metadata after opening
///
/// # Arguments
/// * `path` - The path to the file to read
/// * `file_description` - Description of the file for error messages
/// * `max_size` - Maximum allowed file size in bytes
///
/// # Returns
/// The file contents as a String
///
/// # Errors
/// Returns appropriate `SbomError` variants for various failure modes
pub fn read_file_with_security(
    path: &Path,
    file_description: &str,
    max_size: u64,
) -> Result<String> {
    // Validate and get initial metadata
    let validation = validate_and_get_metadata(path, file_description, max_size)?;
    let initial_size = validation.metadata.len();

    // Open file
    let mut file = File::open(path).map_err(|e| SbomError::FileReadError {
        path: path.to_path_buf(),
        details: format!("Failed to open {}: {}", file_description, e),
    })?;

    // TOCTOU mitigation: Re-check metadata on the opened file descriptor
    let fd_metadata = file.metadata().map_err(|e| SbomError::FileReadError {
        path: path.to_path_buf(),
        details: format!(
            "Failed to read {} metadata after opening: {}",
            file_description, e
        ),
    })?;

    // Verify file hasn't changed (same size indicates likely same file)
    if fd_metadata.len() != initial_size {
        return Err(SbomError::SecurityError {
            path: path.to_path_buf(),
            reason: "File changed between validation and reading".to_string(),
            hint: "This may indicate a TOCTOU attack. Please try again.".to_string(),
        }
        .into());
    }

    // Read file contents
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| SbomError::FileReadError {
            path: path.to_path_buf(),
            details: format!("Failed to read {}: {}", file_description, e),
        })?;

    Ok(contents)
}

/// Validates that a directory path is safe.
///
/// This function validates:
/// - Path exists
/// - Path is not a symbolic link
/// - Path is a directory
/// - Path can be canonicalized (no path traversal issues)
///
/// # Arguments
/// * `path` - The directory path to validate
///
/// # Errors
/// Returns `SbomError::InvalidProjectPath` for any validation failure
pub fn validate_directory_path(path: &Path) -> Result<()> {
    // Check existence
    if !path.exists() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Directory does not exist".to_string(),
        }
        .into());
    }

    // Get metadata to check for symlinks
    let metadata = fs::symlink_metadata(path).map_err(|e| SbomError::InvalidProjectPath {
        path: path.to_path_buf(),
        reason: format!("Failed to read path metadata: {}", e),
    })?;

    // Security check: Reject symbolic links
    if metadata.is_symlink() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Security: Project path is a symbolic link. For security reasons, symbolic links are not allowed.".to_string(),
        }
        .into());
    }

    // Check it's a directory
    if !path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Not a directory".to_string(),
        }
        .into());
    }

    // Canonicalize to prevent path traversal
    let canonical_path = path
        .canonicalize()
        .map_err(|e| SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: format!("Failed to canonicalize path: {}", e),
        })?;

    // Final check on canonicalized path
    if !canonical_path.is_dir() {
        return Err(SbomError::InvalidProjectPath {
            path: path.to_path_buf(),
            reason: "Resolved path is not a directory".to_string(),
        }
        .into());
    }

    Ok(())
}

/// Validates that a path is not a symbolic link
///
/// # Security
/// This function uses `symlink_metadata()` instead of `metadata()` to ensure
/// we check the symlink itself, not the target it points to.
///
/// # Arguments
/// * `path` - The path to validate
/// * `operation` - Description of the operation (e.g., "read", "write") for error messages
///
/// # Errors
/// Returns an error if the path is a symbolic link or if metadata cannot be read
pub fn validate_not_symlink(path: &Path, operation: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read metadata for {} operation on {}: {}",
            operation,
            path.display(),
            e
        )
    })?;

    if metadata.is_symlink() {
        anyhow::bail!(
            "Security: {} is a symbolic link. For security reasons, {} operations on symbolic links are not allowed.",
            path.display(),
            operation
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_validate_not_symlink_regular_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = validate_not_symlink(&file_path, "read");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_not_symlink_nonexistent() {
        let path = PathBuf::from("/nonexistent/file.txt");
        let result = validate_not_symlink(&path, "read");
        assert!(result.is_err());
    }

    #[test]
    fn test_max_file_size_constant() {
        assert_eq!(MAX_FILE_SIZE, 100 * 1024 * 1024); // 100 MB
    }

    #[test]
    fn test_validate_and_get_metadata_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let result = validate_and_get_metadata(&file_path, "test file", MAX_FILE_SIZE);
        assert!(result.is_ok());
        let validation = result.unwrap();
        assert!(validation.metadata.is_file());
        assert_eq!(validation.metadata.len(), 12); // "test content" = 12 bytes
    }

    #[test]
    fn test_validate_and_get_metadata_file_too_large() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = validate_and_get_metadata(&file_path, "test file", 1); // 1 byte limit
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("too large"));
    }

    #[test]
    fn test_validate_and_get_metadata_directory() {
        let temp_dir = TempDir::new().unwrap();

        let result = validate_and_get_metadata(temp_dir.path(), "test dir", MAX_FILE_SIZE);
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("not a regular file"));
    }

    #[test]
    fn test_validate_and_get_metadata_nonexistent() {
        let path = PathBuf::from("/nonexistent/file.txt");

        let result = validate_and_get_metadata(&path, "test file", MAX_FILE_SIZE);
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Failed to read"));
    }

    #[test]
    fn test_read_file_with_security_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let result = read_file_with_security(&file_path, "test file", MAX_FILE_SIZE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello world");
    }

    #[test]
    fn test_read_file_with_security_file_not_found() {
        let path = PathBuf::from("/nonexistent/file.txt");

        let result = read_file_with_security(&path, "test file", MAX_FILE_SIZE);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_with_security_directory() {
        let temp_dir = TempDir::new().unwrap();

        let result = read_file_with_security(temp_dir.path(), "test dir", MAX_FILE_SIZE);
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("not a regular file"));
    }

    #[test]
    fn test_validate_directory_path_success() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_directory_path(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_directory_path_nonexistent() {
        let path = PathBuf::from("/nonexistent/directory");
        let result = validate_directory_path(&path);
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Directory does not exist"));
    }

    #[test]
    fn test_validate_directory_path_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = validate_directory_path(&file_path);
        assert!(result.is_err());
        let err_string = format!("{}", result.unwrap_err());
        assert!(err_string.contains("Not a directory"));
    }
}
