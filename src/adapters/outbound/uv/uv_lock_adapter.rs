use anyhow::{anyhow, Result};
use async_trait::async_trait;
use pep440_rs::Version;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

use super::UvWorkspaceReader;
use crate::ports::outbound::WorkspaceReader;
use crate::sbom_generation::domain::{
    SimulationResult, TargetedSimulationOutcome, UvLockSimulator,
};
use crate::shared::security::{read_file_with_security, MAX_FILE_SIZE};

/// Program name used to invoke the `uv` CLI (resolved via PATH).
const UV_PROGRAM: &str = "uv";

/// Upper bound on a package name accepted by `simulate_upgrade_to`.
const MAX_PACKAGE_NAME_LEN: usize = 200;

/// Upper bound on a version string accepted by `simulate_upgrade_to`.
const MAX_VERSION_LEN: usize = 100;

/// Adapter that implements [`UvLockSimulator`] by shelling out to the `uv` CLI.
///
/// Uses a temporary directory strategy: copies `pyproject.toml` and `uv.lock`
/// (plus, for a uv workspace root, every member's `pyproject.toml`) to a temp dir, runs `uv lock --upgrade-package <pkg>` (or `<pkg>==<version>`
/// for [`UvLockSimulator::simulate_upgrade_to`]), then parses the resulting lock
/// file to determine resolved versions.
pub struct UvLockAdapter;

impl UvLockAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Parse a uv.lock TOML content and return a map of package name → version.
    fn parse_versions(content: &str) -> Result<HashMap<String, String>> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct UvLock {
            package: Vec<UvPackage>,
        }

        #[derive(Deserialize)]
        struct UvPackage {
            name: String,
            version: String,
        }

        let lockfile: UvLock =
            toml::from_str(content).map_err(|e| anyhow!("Failed to parse uv.lock: {}", e))?;

        Ok(lockfile
            .package
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect())
    }

    /// Returns whether `<program> --version` runs and exits successfully.
    async fn uv_available(program: &OsStr) -> bool {
        tokio::process::Command::new(program)
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Verifies the project files exist and copies them into a fresh temp dir.
    ///
    /// Every file is read with `read_file_with_security` (symlinks and
    /// non-regular files rejected, size bounded, metadata re-verified after
    /// opening) and written into the sandbox, rather than copied with
    /// `std::fs::copy`, which would follow a symlink.
    ///
    /// The returned `TempDir` removes itself when dropped, so the original
    /// project's `uv.lock` is never touched.
    fn prepare_sandbox(project_path: &Path) -> Result<tempfile::TempDir> {
        let pyproject_src = project_path.join("pyproject.toml");
        let lockfile_src = project_path.join("uv.lock");

        if !pyproject_src.exists() {
            return Err(anyhow!(
                "pyproject.toml not found in: {}",
                project_path.display()
            ));
        }
        if !lockfile_src.exists() {
            return Err(anyhow!("uv.lock not found in: {}", project_path.display()));
        }

        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| anyhow!("Failed to create temp directory: {}", e))?;

        Self::copy_checked(&pyproject_src, &temp_dir.path().join("pyproject.toml"))
            .map_err(|e| anyhow!("Failed to copy pyproject.toml to temp dir: {}", e))?;
        Self::copy_checked(&lockfile_src, &temp_dir.path().join("uv.lock"))
            .map_err(|e| anyhow!("Failed to copy uv.lock to temp dir: {}", e))?;

        Self::copy_workspace_member_manifests(project_path, temp_dir.path())?;

        Ok(temp_dir)
    }

    /// For a uv workspace root, copies each member's `pyproject.toml` into
    /// `sandbox` at the same relative path, so `uv lock` in the sandbox sees
    /// the whole workspace (#969). A non-workspace lockfile has no members,
    /// so this is a no-op for single projects.
    ///
    /// Member paths come from `uv.lock` and are untrusted, so a member is
    /// copied only when all of these hold:
    /// - its path is lexically inside `project_path` (no `..`, no absolute path);
    /// - its directory, with symlinks resolved, is still inside the resolved
    ///   `project_path` (a symlinked member directory pointing elsewhere is
    ///   skipped);
    /// - its `pyproject.toml` passes `read_file_with_security` (not a symlink,
    ///   a regular file, size bounded).
    ///
    /// A member failing any check, or without a `pyproject.toml`, is skipped,
    /// and `uv lock` in the sandbox then reports what is missing.
    ///
    /// # Errors
    /// Returns an error when the lockfile's member list cannot be read, or a
    /// validated manifest cannot be written into the sandbox.
    fn copy_workspace_member_manifests(project_path: &Path, sandbox: &Path) -> Result<()> {
        let members = UvWorkspaceReader::new().read_workspace_members(project_path)?;
        if members.is_empty() {
            return Ok(());
        }
        let canonical_root = project_path
            .canonicalize()
            .map_err(|e| anyhow!("Failed to resolve workspace root: {}", e))?;
        for member in members {
            let Some(relative) = Self::member_relative_path(project_path, &member.absolute_path)
            else {
                continue;
            };
            let member_dir = project_path.join(&relative);
            let inside_root = member_dir
                .canonicalize()
                .is_ok_and(|resolved| resolved.starts_with(&canonical_root));
            if !inside_root {
                continue;
            }
            let Ok(content) = read_file_with_security(
                &member_dir.join("pyproject.toml"),
                "workspace member pyproject.toml",
                MAX_FILE_SIZE,
            ) else {
                continue;
            };
            let target_dir = sandbox.join(&relative);
            std::fs::create_dir_all(&target_dir).map_err(|e| {
                anyhow!(
                    "Failed to create workspace member directory in temp dir: {}",
                    e
                )
            })?;
            std::fs::write(target_dir.join("pyproject.toml"), content).map_err(|e| {
                anyhow!(
                    "Failed to copy workspace member pyproject.toml to temp dir: {}",
                    e
                )
            })?;
        }
        Ok(())
    }

    /// Reads `source` with `read_file_with_security` and writes it to `target`.
    fn copy_checked(source: &Path, target: &Path) -> Result<()> {
        let content = read_file_with_security(source, "project file", MAX_FILE_SIZE)?;
        std::fs::write(target, content)?;
        Ok(())
    }

    /// The path of `member_path` relative to `root`, or `None` when it is not
    /// strictly inside `root` (only plain, non-empty path components).
    fn member_relative_path(root: &Path, member_path: &Path) -> Option<PathBuf> {
        let relative = member_path.strip_prefix(root).ok()?;
        let mut components = relative.components().peekable();
        components.peek()?;
        components
            .all(|component| matches!(component, Component::Normal(_)))
            .then(|| relative.to_path_buf())
    }

    /// Runs `<program> lock --upgrade-package <upgrade_arg>` in `dir` with a
    /// 60-second timeout. `upgrade_arg` is passed as a single process argument;
    /// no shell is involved.
    async fn run_uv_lock_upgrade(program: &OsStr, dir: &Path, upgrade_arg: &str) -> Result<Output> {
        timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(program)
                .args(["lock", "--upgrade-package", upgrade_arg])
                .current_dir(dir)
                .output(),
        )
        .await
        .map_err(|_| anyhow!("uv lock command timed out after 60 seconds"))?
        .map_err(|e| anyhow!("Failed to run uv lock: {}", e))
    }

    /// Rejects package names and versions that are not safe to hand to `uv`.
    ///
    /// Both values come from advisory data and are untrusted. The name must
    /// match the PEP 508 name charset (which also rules out a leading `-`, so it
    /// cannot be read as an option); the version must use only PEP 440
    /// characters and parse as a PEP 440 version. The charset check runs first
    /// because `pep440_rs` tolerates surrounding whitespace. Returns the parsed
    /// target version on success.
    fn validate_upgrade_target(package_name: &str, target_version: &str) -> Result<Version> {
        let name_bytes = package_name.as_bytes();
        let name_valid = !name_bytes.is_empty()
            && name_bytes.len() <= MAX_PACKAGE_NAME_LEN
            && name_bytes[0].is_ascii_alphanumeric()
            && name_bytes[name_bytes.len() - 1].is_ascii_alphanumeric()
            && name_bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !name_valid {
            return Err(anyhow!(
                "Security: invalid package name for upgrade simulation: {:?}",
                package_name
            ));
        }

        let version_charset_valid = !target_version.is_empty()
            && target_version.len() <= MAX_VERSION_LEN
            && !target_version.starts_with('-')
            && target_version.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'!' | b'_' | b'-')
            });
        let parsed = Version::from_str(target_version).ok();
        match parsed {
            Some(version) if version_charset_valid => Ok(version),
            _ => Err(anyhow!(
                "Security: invalid target version for upgrade simulation: {:?}",
                target_version
            )),
        }
    }

    /// PEP 503 name normalization: lowercase, and runs of `-`, `_`, `.` collapse
    /// to a single `-`.
    fn normalize_name(name: &str) -> String {
        let mut normalized = String::with_capacity(name.len());
        let mut previous_was_separator = false;
        for c in name.trim().chars() {
            if matches!(c, '-' | '_' | '.') {
                if !previous_was_separator {
                    normalized.push('-');
                }
                previous_was_separator = true;
            } else {
                normalized.push(c.to_ascii_lowercase());
                previous_was_separator = false;
            }
        }
        normalized
    }

    /// Summarizes a failed `uv lock` run as its trimmed stderr, falling back to
    /// the exit status when stderr is empty.
    fn summarize_stderr(stderr: &[u8], status: ExitStatus) -> String {
        let text = String::from_utf8_lossy(stderr);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            format!("uv lock exited with {}", status)
        } else {
            trimmed.to_string()
        }
    }

    /// Implementation of [`UvLockSimulator::simulate_upgrade_to`] with the
    /// `uv` program injectable, so tests can point it at a stub or a missing
    /// binary without mutating the process-global PATH.
    async fn simulate_upgrade_to_with(
        program: &OsStr,
        package_name: &str,
        target_version: &str,
        project_path: &Path,
    ) -> Result<TargetedSimulationOutcome> {
        // 1. Validate untrusted input before anything is executed
        let target = Self::validate_upgrade_target(package_name, target_version)?;

        // 2. Report a missing uv as a distinguishable outcome, not an error
        if !Self::uv_available(program).await {
            return Ok(TargetedSimulationOutcome::SimulatorUnavailable);
        }

        // 3. Copy the project into a sandbox and run the targeted upgrade
        let temp_dir = Self::prepare_sandbox(project_path)?;
        let upgrade_arg = format!("{}=={}", package_name, target_version);
        let run_output = Self::run_uv_lock_upgrade(program, temp_dir.path(), &upgrade_arg).await?;

        if !run_output.status.success() {
            return Ok(TargetedSimulationOutcome::ResolutionFailed {
                reason: Self::summarize_stderr(&run_output.stderr, run_output.status),
            });
        }

        // 4. Parse the resulting uv.lock and compare against the target
        let new_content = std::fs::read_to_string(temp_dir.path().join("uv.lock"))
            .map_err(|e| anyhow!("Failed to read resulting uv.lock: {}", e))?;
        let new_versions = Self::parse_versions(&new_content)?;

        let normalized_name = Self::normalize_name(package_name);
        let Some(resolved_version) = new_versions
            .iter()
            .find(|(k, _)| Self::normalize_name(k) == normalized_name)
            .map(|(_, v)| v.clone())
        else {
            return Ok(TargetedSimulationOutcome::ResolutionFailed {
                reason: format!("'{}' not present in resolved uv.lock", package_name),
            });
        };

        let Ok(resolved) = Version::from_str(&resolved_version) else {
            return Ok(TargetedSimulationOutcome::ResolutionFailed {
                reason: format!(
                    "unparseable resolved version '{}' for '{}'",
                    resolved_version, package_name
                ),
            });
        };

        if resolved >= target {
            Ok(TargetedSimulationOutcome::Resolved { resolved_version })
        } else {
            Ok(TargetedSimulationOutcome::ResolutionFailed {
                reason: format!(
                    "'{}' resolved to {}, older than target {}",
                    package_name, resolved_version, target_version
                ),
            })
        }
    }
}

impl Default for UvLockAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UvLockSimulator for UvLockAdapter {
    async fn simulate_upgrade(
        &self,
        package_name: &str,
        project_path: &Path,
    ) -> Result<SimulationResult> {
        let program = OsStr::new(UV_PROGRAM);

        // 1. Verify uv is available in PATH
        if !Self::uv_available(program).await {
            return Err(anyhow!(
                "`uv` CLI not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
            ));
        }

        // 2-3. Verify required files exist and copy them into a temp directory
        let temp_dir = Self::prepare_sandbox(project_path)?;

        // 4. Run: uv lock --upgrade-package <package_name> with 60-second timeout
        let run_output = Self::run_uv_lock_upgrade(program, temp_dir.path(), package_name).await?;

        if !run_output.status.success() {
            let stderr = String::from_utf8_lossy(&run_output.stderr);
            return Err(anyhow!("uv lock --upgrade-package failed: {}", stderr));
        }

        // 5. Parse the resulting uv.lock
        let new_content = std::fs::read_to_string(temp_dir.path().join("uv.lock"))
            .map_err(|e| anyhow!("Failed to read resulting uv.lock: {}", e))?;
        let new_versions = Self::parse_versions(&new_content)?;

        // 6. Find the upgraded version (case-insensitive lookup for robustness)
        let package_name_lower = package_name.to_lowercase();
        let upgraded_to_version = new_versions
            .iter()
            .find(|(k, _)| k.to_lowercase() == package_name_lower)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| anyhow!("Package '{}' not found in resulting uv.lock", package_name))?;

        // 7. Return result (temp_dir is dropped here, cleaning up automatically)
        Ok(SimulationResult {
            upgraded_to_version,
            resolved_versions: new_versions,
        })
    }

    async fn simulate_upgrade_to(
        &self,
        package_name: &str,
        target_version: &str,
        project_path: &Path,
    ) -> Result<TargetedSimulationOutcome> {
        Self::simulate_upgrade_to_with(
            OsStr::new(UV_PROGRAM),
            package_name,
            target_version,
            project_path,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_versions_success() {
        let content = r#"
version = 1
revision = 2

[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"
"#;
        let versions = UvLockAdapter::parse_versions(content).unwrap();
        assert_eq!(versions.get("requests").map(|s| s.as_str()), Some("2.31.0"));
        assert_eq!(versions.get("urllib3").map(|s| s.as_str()), Some("2.0.7"));
    }

    #[test]
    fn test_parse_versions_invalid_toml() {
        let content = "invalid [[[ toml content";
        let result = UvLockAdapter::parse_versions(content);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to parse uv.lock"));
    }

    #[test]
    fn test_parse_versions_empty_packages() {
        let content = r#"
version = 1

[[package]]
name = "mypackage"
version = "0.1.0"
"#;
        let versions = UvLockAdapter::parse_versions(content).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions.get("mypackage").map(|s| s.as_str()), Some("0.1.0"));
    }

    #[test]
    fn test_parse_versions_from_before_fixture() {
        let content = include_str!("../../../../tests/fixtures/sample_uv_lock_before.lock");
        let versions = UvLockAdapter::parse_versions(content).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions.get("requests").map(|s| s.as_str()), Some("2.31.0"));
        assert_eq!(versions.get("urllib3").map(|s| s.as_str()), Some("1.26.5"));
        assert_eq!(
            versions.get("certifi").map(|s| s.as_str()),
            Some("2022.12.7")
        );
    }

    #[test]
    fn test_parse_versions_from_after_fixture_builds_simulation_result() {
        let content = include_str!("../../../../tests/fixtures/sample_uv_lock_after.lock");
        let resolved_versions = UvLockAdapter::parse_versions(content).unwrap();

        // Reconstruct what simulate_upgrade() would return after upgrading "requests"
        let package_name = "requests";
        let upgraded_to_version = resolved_versions
            .iter()
            .find(|(k, _)| k.to_lowercase() == package_name)
            .map(|(_, v)| v.clone())
            .expect("requests must appear in after fixture");

        let sim_result = SimulationResult {
            upgraded_to_version,
            resolved_versions,
        };

        assert_eq!(sim_result.upgraded_to_version, "2.32.3");
        assert_eq!(
            sim_result
                .resolved_versions
                .get("urllib3")
                .map(|s| s.as_str()),
            Some("2.2.1")
        );
        assert_eq!(
            sim_result
                .resolved_versions
                .get("certifi")
                .map(|s| s.as_str()),
            Some("2024.2.2")
        );
    }

    // --- simulate_upgrade_to (#966) ---

    fn repo_path(relative: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    /// Temp project holding a minimal pyproject.toml and the "before" fixture
    /// lock (requests 2.31.0) as its uv.lock.
    fn make_project() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"stub-project\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::copy(
            repo_path("tests/fixtures/sample_uv_lock_before.lock"),
            dir.path().join("uv.lock"),
        )
        .unwrap();
        dir
    }

    fn real_uv_available() -> bool {
        std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn test_simulate_upgrade_to_missing_uv_is_simulator_unavailable() {
        let project = make_project();
        let program = repo_path("tests/fixtures/uv_stub/nonexistent/uv");
        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests",
            "2.32.0",
            project.path(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, TargetedSimulationOutcome::SimulatorUnavailable);
    }

    #[tokio::test]
    async fn test_simulate_upgrade_to_rejects_invalid_input_before_running_uv() {
        let project = make_project();
        // A missing program would yield SimulatorUnavailable if validation were
        // skipped, so an Err here proves validation runs first.
        let program = repo_path("tests/fixtures/uv_stub/nonexistent/uv");
        let result = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests; rm -rf /",
            "2.32.0",
            project.path(),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("Security"));
    }

    #[test]
    fn test_validate_upgrade_target_rejects_unsafe_names() {
        for name in [
            "",
            "requests; rm -rf /",
            "req uests",
            "-r",
            "$(x)",
            "requests-",
            "requests`id`",
            "requests|cat",
        ] {
            assert!(
                UvLockAdapter::validate_upgrade_target(name, "2.32.0").is_err(),
                "name {:?} should be rejected",
                name
            );
        }
        let too_long = "a".repeat(MAX_PACKAGE_NAME_LEN + 1);
        assert!(UvLockAdapter::validate_upgrade_target(&too_long, "2.32.0").is_err());
    }

    #[test]
    fn test_validate_upgrade_target_rejects_unsafe_versions() {
        for version in [
            "",
            "2.31.0 ",
            " 2.31.0",
            "2.31.0;id",
            "--x",
            ">=2",
            "abc",
            "2.*",
        ] {
            assert!(
                UvLockAdapter::validate_upgrade_target("requests", version).is_err(),
                "version {:?} should be rejected",
                version
            );
        }
    }

    #[test]
    fn test_validate_upgrade_target_accepts_valid_pep508_names_and_pep440_versions() {
        for (name, version) in [
            ("requests", "2.32.0"),
            ("Foo_Bar.baz", "1.0"),
            ("a", "1!2.0.post1+local.1"),
            ("zope.interface", "6.0rc1"),
        ] {
            assert!(
                UvLockAdapter::validate_upgrade_target(name, version).is_ok(),
                "{}=={} should be accepted",
                name,
                version
            );
        }
    }

    #[test]
    fn test_normalize_name_follows_pep503() {
        assert_eq!(UvLockAdapter::normalize_name("Foo_Bar.baz"), "foo-bar-baz");
        assert_eq!(UvLockAdapter::normalize_name("a--_.b"), "a-b");
        assert_eq!(UvLockAdapter::normalize_name("Requests"), "requests");
    }

    #[cfg(unix)]
    #[test]
    fn test_summarize_stderr_trims_and_falls_back_to_exit_status() {
        use std::os::unix::process::ExitStatusExt;
        let status = ExitStatus::from_raw(1 << 8);
        assert_eq!(
            UvLockAdapter::summarize_stderr(b"  conflict detail\n", status),
            "conflict detail"
        );
        assert!(UvLockAdapter::summarize_stderr(b" \n", status).starts_with("uv lock exited with"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_resolved_at_or_above_target_keeps_original_lock() {
        let project = make_project();
        let original_lock = std::fs::read(project.path().join("uv.lock")).unwrap();
        let program = repo_path("tests/fixtures/uv_stub/success/uv");

        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests",
            "2.32.0",
            project.path(),
        )
        .await
        .unwrap();

        // The stub resolves 2.32.3, which is newer than the 2.32.0 target
        assert_eq!(
            outcome,
            TargetedSimulationOutcome::Resolved {
                resolved_version: "2.32.3".to_string()
            }
        );
        assert_eq!(
            std::fs::read(project.path().join("uv.lock")).unwrap(),
            original_lock
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_matches_package_name_by_pep503() {
        let project = make_project();
        let program = repo_path("tests/fixtures/uv_stub/success/uv");
        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "Requests",
            "2.32.3",
            project.path(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            TargetedSimulationOutcome::Resolved {
                resolved_version: "2.32.3".to_string()
            }
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_older_than_target_is_resolution_failure() {
        let project = make_project();
        let program = repo_path("tests/fixtures/uv_stub/success/uv");
        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests",
            "2.33.0",
            project.path(),
        )
        .await
        .unwrap();
        match outcome {
            TargetedSimulationOutcome::ResolutionFailed { reason } => {
                assert!(reason.contains("older than target 2.33.0"), "{}", reason)
            }
            other => panic!("expected ResolutionFailed, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_package_missing_from_lock_is_resolution_failure() {
        let project = make_project();
        let program = repo_path("tests/fixtures/uv_stub/success/uv");
        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "urllib4",
            "1.0",
            project.path(),
        )
        .await
        .unwrap();
        match outcome {
            TargetedSimulationOutcome::ResolutionFailed { reason } => {
                assert!(reason.contains("not present"), "{}", reason)
            }
            other => panic!("expected ResolutionFailed, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_conflict_captures_uv_stderr() {
        let project = make_project();
        let program = repo_path("tests/fixtures/uv_stub/conflict/uv");
        let outcome = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests",
            "2.31.0",
            project.path(),
        )
        .await
        .unwrap();
        match outcome {
            TargetedSimulationOutcome::ResolutionFailed { reason } => {
                assert!(reason.contains("unsatisfiable"), "{}", reason)
            }
            other => panic!("expected ResolutionFailed, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_simulate_upgrade_to_missing_pyproject_is_error() {
        let project = tempfile::TempDir::new().unwrap();
        let program = repo_path("tests/fixtures/uv_stub/success/uv");
        let result = UvLockAdapter::simulate_upgrade_to_with(
            program.as_os_str(),
            "requests",
            "2.32.0",
            project.path(),
        )
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pyproject.toml not found"));
    }

    // Real `uv` (needs network access to PyPI, so these fail on an offline
    // machine that has `uv` installed); skipped when `uv` is not on PATH,
    // matching the `src/cli/runner.rs` precedent. CI runners do not install
    // `uv`, so the stub-based tests above are the deterministic ones.

    #[tokio::test]
    async fn test_simulate_upgrade_to_real_uv_resolves_suggest_fix_project() {
        if !real_uv_available() {
            return;
        }
        let project = repo_path("examples/suggest-fix-project");
        let original_lock = std::fs::read(project.join("uv.lock")).unwrap();

        let outcome = UvLockAdapter::new()
            .simulate_upgrade_to("requests", "2.32.0", &project)
            .await
            .unwrap();

        match outcome {
            TargetedSimulationOutcome::Resolved { resolved_version } => {
                let resolved = Version::from_str(&resolved_version).unwrap();
                assert!(resolved >= Version::from_str("2.32.0").unwrap());
            }
            other => panic!("expected Resolved, got {:?}", other),
        }
        assert_eq!(
            std::fs::read(project.join("uv.lock")).unwrap(),
            original_lock
        );
    }

    #[tokio::test]
    async fn test_simulate_upgrade_to_real_uv_conflict_in_sample_project() {
        if !real_uv_available() {
            return;
        }
        // sample-project pins requests==2.25.0, so 2.31.0 is unsatisfiable
        let project = repo_path("examples/sample-project");
        let outcome = UvLockAdapter::new()
            .simulate_upgrade_to("requests", "2.31.0", &project)
            .await
            .unwrap();
        match outcome {
            TargetedSimulationOutcome::ResolutionFailed { reason } => {
                assert!(reason.contains("unsatisfiable"), "{}", reason)
            }
            other => panic!("expected ResolutionFailed, got {:?}", other),
        }
    }

    // --- workspace sandbox (#969) ---

    /// Workspace root whose uv.lock lists `packages/api` and an untrusted
    /// `../outside` member, each with a pyproject.toml on disk.
    fn make_workspace() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("ws");
        std::fs::create_dir_all(root.join("packages/api")).unwrap();
        std::fs::create_dir_all(dir.path().join("outside")).unwrap();
        std::fs::write(
            root.join("pyproject.toml"),
            "[tool.uv.workspace]\nmembers = [\"packages/api\"]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("packages/api/pyproject.toml"),
            "[project]\nname = \"api\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("outside/pyproject.toml"),
            "[project]\nname = \"outside\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("uv.lock"),
            r#"version = 1

[manifest]
members = ["api", "outside"]

[[package]]
name = "api"
version = "0.1.0"
source = { virtual = "packages/api" }

[[package]]
name = "outside"
version = "0.1.0"
source = { virtual = "../outside" }
"#,
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_prepare_sandbox_copies_workspace_member_manifests_inside_root_only() {
        let dir = make_workspace();
        let root = dir.path().join("ws");

        let sandbox = UvLockAdapter::prepare_sandbox(&root).unwrap();

        assert_eq!(
            std::fs::read_to_string(sandbox.path().join("packages/api/pyproject.toml")).unwrap(),
            "[project]\nname = \"api\"\nversion = \"0.1.0\"\n"
        );
        assert!(!sandbox.path().join("../outside/pyproject.toml").exists());
        let entries: Vec<_> = std::fs::read_dir(sandbox.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(!entries.contains(&"outside".to_string()), "{entries:?}");
    }

    #[cfg(unix)]
    #[test]
    fn test_prepare_sandbox_skips_symlinked_member_directory_and_manifest() {
        let dir = make_workspace();
        let root = dir.path().join("ws");
        // `packages/api` now points outside the root.
        std::fs::remove_dir_all(root.join("packages/api")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("outside"), root.join("packages/api")).unwrap();

        let sandbox = UvLockAdapter::prepare_sandbox(&root).unwrap();
        assert!(!sandbox.path().join("packages/api/pyproject.toml").exists());

        // A real member directory whose pyproject.toml is a symlink.
        std::fs::remove_file(root.join("packages/api")).unwrap();
        std::fs::create_dir_all(root.join("packages/api")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("outside/pyproject.toml"),
            root.join("packages/api/pyproject.toml"),
        )
        .unwrap();

        let sandbox = UvLockAdapter::prepare_sandbox(&root).unwrap();
        assert!(!sandbox.path().join("packages/api/pyproject.toml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_prepare_sandbox_rejects_symlinked_root_pyproject() {
        let project = make_project();
        let real = project.path().join("real.toml");
        std::fs::rename(project.path().join("pyproject.toml"), &real).unwrap();
        std::os::unix::fs::symlink(&real, project.path().join("pyproject.toml")).unwrap();

        let err = UvLockAdapter::prepare_sandbox(project.path()).unwrap_err();

        assert!(err.to_string().contains("pyproject.toml"), "{err}");
    }

    #[test]
    fn test_prepare_sandbox_single_project_copies_only_root_files() {
        let project = make_project();

        let sandbox = UvLockAdapter::prepare_sandbox(project.path()).unwrap();

        let mut entries: Vec<_> = std::fs::read_dir(sandbox.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        entries.sort();
        assert_eq!(entries, vec!["pyproject.toml", "uv.lock"]);
    }

    #[test]
    fn test_member_relative_path_rejects_paths_outside_root() {
        let root = Path::new("/ws");
        assert_eq!(
            UvLockAdapter::member_relative_path(root, Path::new("/ws/packages/api")),
            Some(PathBuf::from("packages/api"))
        );
        assert_eq!(
            UvLockAdapter::member_relative_path(root, Path::new("/ws/../outside")),
            None
        );
        assert_eq!(
            UvLockAdapter::member_relative_path(root, Path::new("/elsewhere/api")),
            None
        );
        assert_eq!(
            UvLockAdapter::member_relative_path(root, Path::new("/ws")),
            None
        );
    }

    #[tokio::test]
    async fn test_simulate_upgrade_to_real_uv_resolves_workspace_root() {
        if !real_uv_available() {
            return;
        }
        let project = repo_path("examples/workspace");
        let original_lock = std::fs::read(project.join("uv.lock")).unwrap();

        let outcome = UvLockAdapter::new()
            .simulate_upgrade_to("starlette", "1.0.0", &project)
            .await
            .unwrap();

        assert!(
            matches!(outcome, TargetedSimulationOutcome::Resolved { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(project.join("uv.lock")).unwrap(),
            original_lock
        );
    }
}
