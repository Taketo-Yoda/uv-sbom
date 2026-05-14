use super::lockfile_parser::parse_lockfile_content;
use crate::ports::outbound::{DiffLockfileReader, DiffSource};
use crate::sbom_generation::domain::Package;
use crate::shared::error::SbomError;
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};
use crate::shared::Result;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct GitLockfileReader;

impl GitLockfileReader {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GitLockfileReader {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffLockfileReader for GitLockfileReader {
    fn read_base_packages(&self, source: &DiffSource, project_path: &Path) -> Result<Vec<Package>> {
        match source {
            DiffSource::GitRef(ref_name) => {
                validate_git_ref(ref_name)?;

                let output = Command::new("git")
                    .args(["show", &format!("{}:uv.lock", ref_name)])
                    .current_dir(project_path)
                    .output()
                    .map_err(|e| SbomError::FileReadError {
                        path: project_path.join("uv.lock"),
                        details: format!(
                            "Failed to invoke git: {}. Ensure `git` is installed and on PATH.",
                            e
                        ),
                    })?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(SbomError::FileReadError {
                        path: project_path.join("uv.lock"),
                        details: format!(
                            "git show {}:uv.lock failed: {}",
                            ref_name,
                            stderr.trim()
                        ),
                    }
                    .into());
                }

                let content = String::from_utf8(output.stdout).map_err(|_| {
                    SbomError::LockfileParseError {
                        path: project_path.join("uv.lock"),
                        details: "git show output is not valid UTF-8".to_string(),
                    }
                })?;

                let (packages, _) = parse_lockfile_content(&content, project_path)?;
                Ok(packages)
            }
            DiffSource::FilePath(path) => {
                let content =
                    read_file_with_security(path, "uv.lock (diff base)", MAX_FILE_SIZE)?;
                let (packages, _) = parse_lockfile_content(&content, project_path)?;
                Ok(packages)
            }
        }
    }
}

/// Validates a git ref against a safe character allowlist to prevent command injection.
///
/// Allowed characters: `[a-zA-Z0-9._/-]`
/// Rejected: empty strings, refs starting with `-` (option injection risk).
fn validate_git_ref(ref_name: &str) -> Result<()> {
    if ref_name.is_empty() {
        return Err(SbomError::SecurityError {
            path: PathBuf::from("<git-ref>"),
            reason: "Git ref must not be empty".to_string(),
            hint: "Provide a valid git ref such as a branch name, tag, or commit SHA.".to_string(),
        }
        .into());
    }

    if ref_name.starts_with('-') {
        return Err(SbomError::SecurityError {
            path: PathBuf::from(ref_name),
            reason: format!("Git ref '{}' must not start with '-'", ref_name),
            hint: "Git refs starting with '-' could be interpreted as command options. Use a valid ref name.".to_string(),
        }
        .into());
    }

    if let Some(c) = ref_name
        .chars()
        .find(|&c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '/' | '-'))
    {
        return Err(SbomError::SecurityError {
            path: PathBuf::from(ref_name),
            reason: format!(
                "Git ref '{}' contains invalid character '{}'",
                ref_name, c
            ),
            hint: "Only alphanumeric characters and '.', '_', '/', '-' are allowed in git refs."
                .to_string(),
        }
        .into());
    }

    Ok(())
}

/// Determines whether `arg` refers to an existing file or a git ref.
///
/// If `arg` resolves to an existing regular file, returns `DiffSource::FilePath`.
/// Otherwise returns `DiffSource::GitRef`. Note: relative paths are resolved
/// against the process working directory, not the project path.
// Dead in the bin target until wired to CLI in a subsequent subtask of #224.
// #[expect(dead_code)] cannot be used: the lib target does not see this as dead code
// (pub fn is reachable by library consumers), making the expectation unfulfilled there.
#[allow(dead_code)]
pub fn determine_diff_source(arg: &str) -> DiffSource {
    let path = Path::new(arg);
    if path.exists() && path.is_file() {
        DiffSource::FilePath(path.to_path_buf())
    } else {
        DiffSource::GitRef(arg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // --- validate_git_ref ---

    #[test]
    fn test_validate_git_ref_accepts_main() {
        assert!(validate_git_ref("main").is_ok());
    }

    #[test]
    fn test_validate_git_ref_accepts_version_tag() {
        assert!(validate_git_ref("v1.0.0").is_ok());
    }

    #[test]
    fn test_validate_git_ref_accepts_short_commit_sha() {
        assert!(validate_git_ref("abc1234").is_ok());
    }

    #[test]
    fn test_validate_git_ref_accepts_feature_branch_with_slash() {
        assert!(validate_git_ref("feature/my-branch").is_ok());
    }

    #[test]
    fn test_validate_git_ref_accepts_remote_tracking_ref() {
        assert!(validate_git_ref("origin/main").is_ok());
    }

    #[test]
    fn test_validate_git_ref_rejects_empty_string() {
        let result = validate_git_ref("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must not be empty"));
    }

    #[test]
    fn test_validate_git_ref_rejects_leading_dash() {
        let result = validate_git_ref("-rf");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not start with '-'"));
    }

    #[test]
    fn test_validate_git_ref_rejects_option_injection() {
        let result = validate_git_ref("--upload-pack=malicious");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_git_ref_rejects_semicolon() {
        let result = validate_git_ref("main;rm");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid character"));
    }

    #[test]
    fn test_validate_git_ref_rejects_space() {
        let result = validate_git_ref("feature branch");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid character"));
    }

    // --- determine_diff_source ---

    #[test]
    fn test_determine_diff_source_returns_file_path_for_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let lock_path = temp_dir.path().join("uv.lock");
        fs::write(&lock_path, "version = 1").unwrap();

        let source = determine_diff_source(lock_path.to_str().unwrap());
        assert_eq!(source, DiffSource::FilePath(lock_path));
    }

    #[test]
    fn test_determine_diff_source_returns_git_ref_for_branch_name() {
        let source = determine_diff_source("main");
        assert_eq!(source, DiffSource::GitRef("main".to_string()));
    }

    #[test]
    fn test_determine_diff_source_returns_git_ref_for_nonexistent_path() {
        let source = determine_diff_source("/nonexistent/path/uv.lock");
        assert_eq!(
            source,
            DiffSource::GitRef("/nonexistent/path/uv.lock".to_string())
        );
    }

    #[test]
    fn test_determine_diff_source_returns_git_ref_for_directory() {
        let temp_dir = TempDir::new().unwrap();
        // A directory is not a file, so it should be treated as a git ref
        let source = determine_diff_source(temp_dir.path().to_str().unwrap());
        assert_eq!(
            source,
            DiffSource::GitRef(temp_dir.path().to_str().unwrap().to_string())
        );
    }
}
