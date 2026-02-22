use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Helper: run uv-sbom with given args, return (exit_code, stdout, stderr)
fn run_uv_sbom(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_uv-sbom"))
        .args(args)
        .output()
        .expect("Failed to execute uv-sbom");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (exit_code, stdout, stderr)
}

/// Helper: create a minimal uv.lock in a temp directory
fn create_test_project() -> TempDir {
    let dir = TempDir::new().unwrap();

    // Create a minimal pyproject.toml
    let pyproject = r#"[project]
name = "test-project"
version = "0.1.0"
"#;
    fs::write(dir.path().join("pyproject.toml"), pyproject).unwrap();

    // Create a minimal uv.lock with packages that have known licenses
    let lock_content = r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "test-project"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;
    fs::write(dir.path().join("uv.lock"), lock_content).unwrap();

    dir
}

// ============================================================
// CLI argument validation tests
// ============================================================

#[test]
fn test_license_allow_without_check_license_fails() {
    let (exit_code, _stdout, stderr) = run_uv_sbom(&["--license-allow", "MIT"]);
    assert_eq!(exit_code, 2, "Expected exit code 2 for invalid args");
    assert!(
        stderr.contains("--check-license"),
        "Should mention --check-license requirement: {}",
        stderr
    );
}

#[test]
fn test_license_deny_without_check_license_fails() {
    let (exit_code, _stdout, stderr) = run_uv_sbom(&["--license-deny", "GPL-*"]);
    assert_eq!(exit_code, 2, "Expected exit code 2 for invalid args");
    assert!(
        stderr.contains("--check-license"),
        "Should mention --check-license requirement: {}",
        stderr
    );
}

// ============================================================
// Config file parsing tests
// ============================================================

#[test]
fn test_config_file_license_policy_valid() {
    let dir = create_test_project();
    let config = r#"
check_license: true
license_policy:
  allow:
    - "MIT"
    - "Apache-2.0"
  deny:
    - "GPL-*"
  unknown: warn
"#;
    fs::write(dir.path().join("uv-sbom.config.yml"), config).unwrap();

    let (exit_code, _stdout, stderr) = run_uv_sbom(&[
        "--path",
        dir.path().to_str().unwrap(),
        "--format",
        "markdown",
    ]);
    // Should run without error (exit 0 or 1 based on results, not 2)
    assert_ne!(
        exit_code, 2,
        "Should not fail with argument errors: {}",
        stderr
    );
}

#[test]
fn test_config_file_invalid_unknown_handling() {
    let dir = create_test_project();
    let config = r#"
license_policy:
  unknown: invalid_value
"#;
    fs::write(dir.path().join("uv-sbom.config.yml"), config).unwrap();

    let (exit_code, _stdout, stderr) = run_uv_sbom(&[
        "--path",
        dir.path().to_str().unwrap(),
        "--format",
        "markdown",
    ]);
    // Should fail with a validation error
    assert_ne!(exit_code, 0, "Should fail for invalid unknown value");
    assert!(
        stderr.contains("license_policy.unknown must be one of"),
        "Should mention valid values: {}",
        stderr
    );
}

// ============================================================
// Integration: --check-license flag tests
// ============================================================

#[test]
fn test_check_license_with_json_format_warns() {
    let dir = create_test_project();
    let (exit_code, _stdout, stderr) = run_uv_sbom(&[
        "--path",
        dir.path().to_str().unwrap(),
        "--check-license",
        "--format",
        "json",
    ]);
    // Should warn about JSON format
    assert!(
        stderr.contains("--check-license has no effect with JSON format"),
        "Should warn about JSON format: {}",
        stderr
    );
    // Should still succeed
    assert_eq!(exit_code, 0);
}
