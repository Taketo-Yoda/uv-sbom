use crate::shared::Result;
use std::fs;
use std::path::Path;

/// Maximum file size for security (100 MB)
/// This prevents DoS attacks via excessively large files
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

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

/// Validates that a path exists and is a regular file (not a directory or symlink)
///
/// # Security
/// This combines existence check, symlink check, and file type check in one operation.
///
/// # Arguments
/// * `path` - The path to validate
/// * `file_description` - Description of the file (e.g., "uv.lock", "pyproject.toml")
///
/// # Errors
/// Returns an error if:
/// - The path doesn't exist
/// - The path is a symbolic link
/// - The path is not a regular file
pub fn validate_regular_file(path: &Path, file_description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read {} metadata: {}",
            file_description,
            e
        )
    })?;

    if metadata.is_symlink() {
        anyhow::bail!(
            "Security: {} is a symbolic link. For security reasons, symbolic links are not allowed.",
            path.display()
        );
    }

    if !metadata.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }

    Ok(())
}

/// Validates file size is within acceptable limits
///
/// # Security
/// This prevents DoS attacks via excessively large files that could consume
/// system resources or cause out-of-memory errors.
///
/// # Arguments
/// * `file_size` - The size of the file in bytes
/// * `path` - The path to the file (for error messages)
/// * `max_size` - Maximum allowed size in bytes
///
/// # Errors
/// Returns an error if the file size exceeds the maximum
pub fn validate_file_size(file_size: u64, path: &Path, max_size: u64) -> Result<()> {
    if file_size > max_size {
        anyhow::bail!(
            "Security: {} is too large ({} bytes). Maximum allowed size is {} bytes.",
            path.display(),
            file_size,
            max_size
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
    fn test_validate_regular_file_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = validate_regular_file(&file_path, "test file");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_regular_file_is_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_regular_file(temp_dir.path(), "test directory");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a regular file"));
    }

    #[test]
    fn test_validate_file_size_within_limit() {
        let path = PathBuf::from("/test/file.txt");
        let result = validate_file_size(1000, &path, MAX_FILE_SIZE);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_file_size_exceeds_limit() {
        let path = PathBuf::from("/test/file.txt");
        let result = validate_file_size(MAX_FILE_SIZE + 1, &path, MAX_FILE_SIZE);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_max_file_size_constant() {
        assert_eq!(MAX_FILE_SIZE, 100 * 1024 * 1024); // 100 MB
    }
}
