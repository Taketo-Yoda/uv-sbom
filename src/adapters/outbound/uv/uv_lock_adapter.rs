use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

use crate::ports::outbound::uv_lock_simulator::{SimulationResult, UvLockSimulator};

/// Adapter that implements [`UvLockSimulator`] by shelling out to the `uv` CLI.
///
/// Uses a temporary directory strategy: copies `pyproject.toml` and `uv.lock`
/// to a temp dir, runs `uv lock --upgrade-package <pkg>`, then parses the
/// resulting lock file to determine resolved versions.
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
        // 1. Verify uv is available in PATH
        let uv_available = tokio::process::Command::new("uv")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !uv_available {
            return Err(anyhow!(
                "`uv` CLI not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh"
            ));
        }

        // 2. Verify required files exist in project_path
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

        // 3. Create temp directory and copy files into it
        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| anyhow!("Failed to create temp directory: {}", e))?;

        std::fs::copy(&pyproject_src, temp_dir.path().join("pyproject.toml"))
            .map_err(|e| anyhow!("Failed to copy pyproject.toml to temp dir: {}", e))?;
        std::fs::copy(&lockfile_src, temp_dir.path().join("uv.lock"))
            .map_err(|e| anyhow!("Failed to copy uv.lock to temp dir: {}", e))?;

        // 4. Run: uv lock --upgrade-package <package_name> with 60-second timeout
        let run_output = timeout(
            Duration::from_secs(60),
            tokio::process::Command::new("uv")
                .args(["lock", "--upgrade-package", package_name])
                .current_dir(temp_dir.path())
                .output(),
        )
        .await
        .map_err(|_| anyhow!("uv lock command timed out after 60 seconds"))?
        .map_err(|e| anyhow!("Failed to run uv lock: {}", e))?;

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
            upgraded_package: package_name.to_string(),
            upgraded_to_version,
            resolved_versions: new_versions,
        })
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
            upgraded_package: package_name.to_string(),
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
}
