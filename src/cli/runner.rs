use owo_colors::OwoColorize;

use crate::shared::Result;

pub fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        "{} {} {}",
        "🚀".bright_yellow(),
        "uv-sbom".bright_cyan().bold(),
        format!("v{}", version).bright_green()
    );
    eprintln!();
}

/// Resolves the effective value of `suggest_fix` after pre-flight validation.
///
/// Returns `false` immediately when `suggest_fix` is `false`.
/// When `suggest_fix` is `true`, verifies that:
/// - the `uv` CLI is available in PATH
/// - `pyproject.toml` exists in the given project directory
///
/// Prints a warning and returns `false` on the first failing condition.
pub fn resolve_suggest_fix(suggest_fix: bool, project_path: &std::path::Path) -> bool {
    if !suggest_fix {
        return false;
    }
    let uv_available = std::process::Command::new("uv")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !uv_available {
        eprintln!(
            "⚠ --suggest-fix requires `uv` CLI. \
             Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
        );
        return false;
    }
    if !project_path.join("pyproject.toml").exists() {
        eprintln!("⚠ --suggest-fix requires pyproject.toml in the project directory.");
        return false;
    }
    true
}

/// Validates that the project path is a valid directory.
///
/// This delegates to `validate_directory_path` in `shared::security`,
/// which provides comprehensive security validation including:
/// - Existence check
/// - Symlink rejection
/// - Directory type verification
/// - Path canonicalization for traversal prevention
pub fn validate_project_path(path: &std::path::Path) -> Result<()> {
    crate::shared::security::validate_directory_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
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

    #[test]
    fn test_resolve_suggest_fix_disabled() {
        let temp_dir = TempDir::new().unwrap();
        // When suggest_fix is false, always returns false without checking anything
        assert!(!resolve_suggest_fix(false, temp_dir.path()));
    }

    #[test]
    fn test_resolve_suggest_fix_missing_pyproject_toml() {
        let temp_dir = TempDir::new().unwrap();
        // No pyproject.toml in temp dir; only meaningful when uv is available
        let uv_available = std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if uv_available {
            assert!(!resolve_suggest_fix(true, temp_dir.path()));
        }
    }

    #[test]
    fn test_resolve_suggest_fix_with_pyproject_toml() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("pyproject.toml"),
            "[project]\nname = \"test\"\n",
        )
        .unwrap();
        let uv_available = std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // Result should match uv availability
        assert_eq!(resolve_suggest_fix(true, temp_dir.path()), uv_available);
    }
}
