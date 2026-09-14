/// End-to-end tests for workspace mode (--workspace flag)
mod workspace_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
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

    /// Copies the workspace fixture into a temp directory and returns it.
    /// This is needed because workspace mode writes sbom.* files inside
    /// the fixture directories, which would pollute the source tree.
    fn setup_workspace_temp() -> TempDir {
        let temp = TempDir::new().expect("failed to create temp dir");
        let src = std::path::Path::new("tests/fixtures/workspace");

        // Copy uv.lock
        fs::copy(src.join("uv.lock"), temp.path().join("uv.lock")).unwrap();

        // Copy packages/api/
        let api_dir = temp.path().join("packages/api");
        fs::create_dir_all(&api_dir).unwrap();
        fs::copy(
            src.join("packages/api/pyproject.toml"),
            api_dir.join("pyproject.toml"),
        )
        .unwrap();

        // Copy packages/worker/
        let worker_dir = temp.path().join("packages/worker");
        fs::create_dir_all(&worker_dir).unwrap();
        fs::copy(
            src.join("packages/worker/pyproject.toml"),
            worker_dir.join("pyproject.toml"),
        )
        .unwrap();

        temp
    }

    /// --workspace generates sbom.json for each member
    #[test]
    fn test_workspace_generates_sbom_per_member() {
        let temp = setup_workspace_temp();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
                "--format",
                "json",
            ])
            .assert()
            .code(0);

        assert!(
            temp.path().join("packages/api/sbom.json").exists(),
            "sbom.json must exist for member api"
        );
        assert!(
            temp.path().join("packages/worker/sbom.json").exists(),
            "sbom.json must exist for member worker"
        );
    }

    /// --workspace generates sbom.md for each member when --format markdown
    #[test]
    fn test_workspace_generates_markdown_sbom_per_member() {
        let temp = setup_workspace_temp();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
                "--format",
                "markdown",
            ])
            .assert()
            .code(0);

        assert!(
            temp.path().join("packages/api/sbom.md").exists(),
            "sbom.md must exist for member api"
        );
        assert!(
            temp.path().join("packages/worker/sbom.md").exists(),
            "sbom.md must exist for member worker"
        );
    }

    /// --workspace on a non-workspace directory exits with error
    #[test]
    fn test_workspace_on_non_workspace_exits_with_error() {
        let temp = TempDir::new().unwrap();
        // Write a minimal non-workspace uv.lock (no [manifest] section)
        fs::write(
            temp.path().join("uv.lock"),
            r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "my-project"
version = "1.0.0"
source = { virtual = "." }
"#,
        )
        .unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
            ])
            .assert()
            .code(3);
    }

    /// --workspace --output is mutually exclusive (clap should reject it)
    #[test]
    fn test_workspace_and_output_are_mutually_exclusive() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "--workspace",
                "--path",
                "tests/fixtures/workspace",
                "--output",
                "/tmp/sbom.json",
            ])
            .assert()
            .code(2);
    }

    /// --workspace with no checks enabled prints no aggregate summary section at all
    #[test]
    fn test_workspace_aggregate_summary_absent_when_no_checks_enabled() {
        let temp = setup_workspace_temp();

        let (exit_code, _stdout, stderr) = run_uv_sbom(&[
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
        ]);

        assert_eq!(exit_code, 0);
        assert!(
            stderr.contains("📦 Workspace SBOM Summary"),
            "existing per-member table must still print: {stderr}"
        );
        assert!(
            !stderr.contains("Workspace Aggregate Summary"),
            "no check was enabled, so no aggregate section should print: {stderr}"
        );
    }

    /// --workspace --check-license prints only the license violations line in the
    /// aggregate summary, not CVE/abandoned/non-PyPI/Python-incompatible lines
    #[test]
    fn test_workspace_aggregate_summary_shows_only_enabled_license_check() {
        let temp = setup_workspace_temp();

        let (exit_code, _stdout, stderr) = run_uv_sbom(&[
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
            "--check-license",
        ]);

        assert_eq!(exit_code, 0);
        assert!(
            stderr.contains("📊 Workspace Aggregate Summary"),
            "aggregate section must print when a check is enabled: {stderr}"
        );
        assert!(
            stderr.contains("Members with license policy violations: none"),
            "the fixture workspace has no third-party packages, so no violations: {stderr}"
        );
        assert!(
            !stderr.contains("Total actionable CVEs"),
            "CVE check was disabled via --no-check-cve, its line must be absent: {stderr}"
        );
        assert!(
            !stderr.contains("abandoned packages"),
            "abandoned check was not requested, its line must be absent: {stderr}"
        );
        assert!(
            !stderr.contains("non-PyPI packages"),
            "non-PyPI check was not requested, its line must be absent: {stderr}"
        );
        assert!(
            !stderr.contains("Python-incompatible"),
            "Python compatibility check was not requested, its line must be absent: {stderr}"
        );
    }

    /// --workspace --check-non-pypi prints only the non-PyPI packages line
    #[test]
    fn test_workspace_aggregate_summary_shows_only_enabled_non_pypi_check() {
        let temp = setup_workspace_temp();

        let (exit_code, _stdout, stderr) = run_uv_sbom(&[
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
            "--check-non-pypi",
        ]);

        assert_eq!(exit_code, 0);
        assert!(stderr.contains("📊 Workspace Aggregate Summary"));
        assert!(stderr.contains("Members with non-PyPI packages: none"));
        assert!(!stderr.contains("Total actionable CVEs"));
        assert!(!stderr.contains("license policy violations"));
    }

    /// --workspace with the CVE check enabled (the default) prints the total actionable
    /// CVE count summed across members
    #[test]
    fn test_workspace_aggregate_summary_shows_cve_total_by_default() {
        let temp = setup_workspace_temp();

        let (exit_code, _stdout, stderr) =
            run_uv_sbom(&["--workspace", "--path", temp.path().to_str().unwrap()]);

        assert_eq!(exit_code, 0);
        assert!(stderr.contains("📊 Workspace Aggregate Summary"));
        assert!(
            stderr.contains("Total actionable CVEs: 0"),
            "the fixture workspace has no third-party packages, so the total is 0: {stderr}"
        );
        assert!(!stderr.contains("license policy violations"));
    }
}
