/// End-to-end tests for config file loading, CLI option merging, and CVE ignore functionality.
///
/// These tests exercise the full flow from config file on disk through CLI invocation
/// to correct output, using `assert_cmd` and `tempfile` for isolated test environments.
use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a minimal uv.lock file for testing.
fn write_uv_lock(dir: &std::path::Path) {
    let uv_lock = r#"version = 1
requires-python = ">=3.8"

[[package]]
name = "test-project"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "certifi" },
]

[[package]]
name = "certifi"
version = "2023.11.17"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/64/62/428ef076be88fa93716b576e4a01f919d25968913e817077a386fcbe4f42/certifi-2023.11.17-py3-none-any.whl", hash = "sha256:e036ab49d5b79556f99cfc2d9320b34cfbe5be05c5871b51de9329f0603b0474" },
]
"#;
    fs::write(dir.join("uv.lock"), uv_lock).unwrap();
}

/// Create a minimal pyproject.toml file for testing.
fn write_pyproject_toml(dir: &std::path::Path) {
    let pyproject = r#"[project]
name = "test-project"
version = "0.1.0"
requires-python = ">=3.8"
dependencies = [
    "certifi",
]
"#;
    fs::write(dir.join("pyproject.toml"), pyproject).unwrap();
}

/// Create a test project directory with uv.lock and pyproject.toml.
fn create_test_project(dir: &std::path::Path) {
    write_uv_lock(dir);
    write_pyproject_toml(dir);
}

/// Write a config file at the specified path.
fn write_config(path: &std::path::Path, content: &str) {
    fs::write(path, content).unwrap();
}

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

// ============================================================================
// Config File Auto-Discovery Tests
// ============================================================================

mod auto_discovery_tests {
    use super::*;

    #[test]
    fn test_auto_discovery_applies_exclude_packages() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        // Config excludes certifi
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
exclude_packages:
  - certifi
"#,
        );

        // Run CLI and capture stdout
        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // certifi should be excluded from output
        assert!(!stdout.contains("\"name\": \"certifi\""));
        // stderr should mention auto-discovery
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Auto-discovered config file"));
    }

    #[test]
    fn test_auto_discovery_applies_format() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
format: markdown
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Markdown output should contain SBOM header
        assert!(stdout.contains("# Software Bill of Materials (SBOM)"));
    }

    #[test]
    fn test_no_config_file_runs_normally() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());
        // No config file - should run with defaults

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Default format is JSON
        assert!(stdout.contains("\"bomFormat\": \"CycloneDX\""));
    }
}

// ============================================================================
// Explicit Config Path (`--config`) Tests
// ============================================================================

mod explicit_config_tests {
    use super::*;

    #[test]
    fn test_explicit_config_path_loads_successfully() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        // Place config at a custom path (not auto-discovery name)
        let config_path = dir.path().join("custom-config.yml");
        write_config(
            &config_path,
            r#"
exclude_packages:
  - certifi
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                dir.path().to_str().unwrap(),
                "-c",
                config_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("\"name\": \"certifi\""));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Loaded config from:"));
    }

    #[test]
    fn test_explicit_config_nonexistent_file_error() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                "tests/fixtures/sample-project",
                "-c",
                "nonexistent-config.yml",
            ])
            .assert()
            .code(3); // ApplicationError
    }
}

// ============================================================================
// CLI + Config Merge Tests
// ============================================================================

mod merge_tests {
    use super::*;

    #[test]
    fn test_cli_and_config_exclude_patterns_merged() {
        let dir = TempDir::new().unwrap();
        let sample_project = fixtures_path().join("sample-project");

        // Copy sample-project files (has 6 packages)
        fs::copy(sample_project.join("uv.lock"), dir.path().join("uv.lock")).unwrap();
        fs::copy(
            sample_project.join("pyproject.toml"),
            dir.path().join("pyproject.toml"),
        )
        .unwrap();

        // Config excludes certifi
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
exclude_packages:
  - certifi
"#,
        );

        // CLI also excludes urllib3 — both should be excluded
        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap(), "-e", "urllib3"])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("\"name\": \"certifi\""));
        assert!(!stdout.contains("\"name\": \"urllib3\""));
        // Other packages should still be present
        assert!(stdout.contains("\"name\": \"requests\""));
    }

    #[test]
    fn test_cli_format_overrides_config() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        // Config sets markdown format
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
format: markdown
"#,
        );

        // CLI explicitly requests JSON — should override config
        // Note: Since clap default is "json", we can't distinguish "user passed --format json"
        // from "default json". So we test the reverse: config=json, CLI=markdown
        let dir2 = TempDir::new().unwrap();
        create_test_project(dir2.path());
        write_config(
            &dir2.path().join("uv-sbom.config.yml"),
            r#"
format: json
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir2.path().to_str().unwrap(), "-f", "markdown"])
            .output()
            .unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("# Software Bill of Materials (SBOM)"));
    }
}

// ============================================================================
// CVE Ignore via Config Tests
// ============================================================================

mod cve_ignore_config_tests {
    use super::*;

    #[test]
    #[ignore = "requires network access to OSV API"]
    fn test_ignore_cve_via_config_file() {
        let dir = TempDir::new().unwrap();

        // Copy vulnerable project files
        let vuln_project = fixtures_path().join("vulnerable_project");
        fs::copy(vuln_project.join("uv.lock"), dir.path().join("uv.lock")).unwrap();
        fs::copy(
            vuln_project.join("pyproject.toml"),
            dir.path().join("pyproject.toml"),
        )
        .unwrap();

        // Config ignores the known CVE
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
check_cve: true
ignore_cves:
  - id: CVE-2023-37920
    reason: "Test fixture - known false positive"
  - id: PYSEC-2023-135
    reason: "Test fixture - duplicate of CVE-2023-37920"
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap(), "-f", "markdown"])
            .output()
            .unwrap();

        // Should succeed because all CVEs are ignored
        assert!(
            output.status.success(),
            "Expected exit code 0 but got {}. stderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Ignored"));
    }

    #[test]
    #[ignore = "requires network access to OSV API"]
    fn test_ignore_cve_via_config_with_check_cve_flag() {
        let dir = TempDir::new().unwrap();

        let vuln_project = fixtures_path().join("vulnerable_project");
        fs::copy(vuln_project.join("uv.lock"), dir.path().join("uv.lock")).unwrap();
        fs::copy(
            vuln_project.join("pyproject.toml"),
            dir.path().join("pyproject.toml"),
        )
        .unwrap();

        // Config only has ignore_cves (no check_cve)
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
ignore_cves:
  - id: CVE-2023-37920
  - id: PYSEC-2023-135
"#,
        );

        // CLI provides --check-cve flag
        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                dir.path().to_str().unwrap(),
                "--check-cve",
                "-f",
                "markdown",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Expected exit code 0. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// ============================================================================
// CVE Ignore via CLI Tests
// ============================================================================

mod cve_ignore_cli_tests {
    use super::*;

    #[test]
    #[ignore = "requires network access to OSV API"]
    fn test_ignore_cve_via_cli_flag() {
        let project_path = fixtures_path().join("vulnerable_project");

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                project_path.to_str().unwrap(),
                "--check-cve",
                "-i",
                "CVE-2023-37920",
                "-i",
                "PYSEC-2023-135",
                "-f",
                "markdown",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Expected exit code 0. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Ignored"));
    }

    #[test]
    #[ignore = "requires network access to OSV API"]
    fn test_ignore_cve_cli_and_config_merged() {
        let dir = TempDir::new().unwrap();

        let vuln_project = fixtures_path().join("vulnerable_project");
        fs::copy(vuln_project.join("uv.lock"), dir.path().join("uv.lock")).unwrap();
        fs::copy(
            vuln_project.join("pyproject.toml"),
            dir.path().join("pyproject.toml"),
        )
        .unwrap();

        // Config ignores one CVE
        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
ignore_cves:
  - id: CVE-2023-37920
    reason: "Config reason"
"#,
        );

        // CLI ignores another CVE — both should be merged
        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                dir.path().to_str().unwrap(),
                "--check-cve",
                "-i",
                "PYSEC-2023-135",
                "-f",
                "markdown",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Expected exit code 0. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires network access to OSV API"]
    fn test_without_ignore_cve_detects_vulnerability() {
        let project_path = fixtures_path().join("vulnerable_project");

        // Without ignoring CVEs, vulnerable project should return exit code 1
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                project_path.to_str().unwrap(),
                "--check-cve",
                "-f",
                "markdown",
            ])
            .assert()
            .code(1); // VulnerabilitiesDetected
    }
}

// ============================================================================
// Error Case Tests
// ============================================================================

mod error_tests {
    use super::*;

    #[test]
    fn test_invalid_yaml_syntax_error() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            "invalid: yaml: [[[broken",
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(3)); // ApplicationError
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Failed to parse config file"));
    }

    #[test]
    fn test_empty_cve_id_validation_error() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
ignore_cves:
  - id: ""
    reason: "empty id should fail"
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(3)); // ApplicationError
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("must not be empty"));
    }

    #[test]
    fn test_explicit_config_not_found_error() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        let missing_config = dir.path().join("does-not-exist.yml");

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                dir.path().to_str().unwrap(),
                "-c",
                missing_config.to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(3)); // ApplicationError
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Failed to read config file"));
    }

    #[test]
    fn test_invalid_yaml_via_explicit_config_error() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        let bad_config = dir.path().join("bad.yml");
        write_config(&bad_config, "not: valid: [yaml: syntax");

        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                dir.path().to_str().unwrap(),
                "-c",
                bad_config.to_str().unwrap(),
            ])
            .assert()
            .code(3);
    }

    #[test]
    fn test_whitespace_only_cve_id_error() {
        let dir = TempDir::new().unwrap();
        create_test_project(dir.path());

        write_config(
            &dir.path().join("uv-sbom.config.yml"),
            r#"
ignore_cves:
  - id: "   "
    reason: "whitespace only"
"#,
        );

        let output = cargo_bin_cmd!("uv-sbom")
            .args(["-p", dir.path().to_str().unwrap()])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(3));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("must not be empty"));
    }
}
