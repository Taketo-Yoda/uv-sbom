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

    /// Writes a minimal non-workspace uv.lock (no [manifest] section) into `dir`.
    fn write_non_workspace_lockfile(dir: &std::path::Path) {
        fs::write(
            dir.join("uv.lock"),
            r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "my-project"
version = "1.0.0"
source = { virtual = "." }
"#,
        )
        .unwrap();
    }

    /// --workspace on a non-workspace directory exits with error, in English by default
    #[test]
    fn test_workspace_on_non_workspace_exits_with_error() {
        let temp = TempDir::new().unwrap();
        write_non_workspace_lockfile(temp.path());

        let (exit_code, _stdout, stderr) = run_uv_sbom(&[
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
        ]);

        assert_eq!(exit_code, 3);
        assert!(
            stderr.contains("No workspace members found. Is this a uv workspace?"),
            "stderr must contain the English no-workspace-members message, got: {stderr}"
        );
    }

    /// --workspace on a non-workspace directory under --lang ja localizes the error
    #[test]
    fn test_workspace_on_non_workspace_exits_with_error_ja() {
        let temp = TempDir::new().unwrap();
        write_non_workspace_lockfile(temp.path());

        let (exit_code, _stdout, stderr) = run_uv_sbom(&[
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
            "--lang",
            "ja",
        ]);

        assert_eq!(exit_code, 3);
        assert!(
            stderr.contains(
                "ワークスペースメンバーが見つかりません。これは uv ワークスペースですか？"
            ),
            "stderr must contain the Japanese no-workspace-members message, got: {stderr}"
        );
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

    /// Writes a revision-3 workspace where member `b` declares a non-`dev`
    /// group (`lint = [black]`, `black -> click`) besides `dev = [mypy]` (#997).
    fn rev3_workspace_with_non_dev_group() -> TempDir {
        let temp = TempDir::new().expect("failed to create temp dir");
        let root = temp.path();
        fs::write(
            root.join("pyproject.toml"),
            "[tool.uv.workspace]\nmembers = [\"packages/a\", \"packages/b\"]\n",
        )
        .unwrap();
        for name in ["a", "b"] {
            let dir = root.join("packages").join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("pyproject.toml"),
                format!(
                    "[project]\nname = \"{name}\"\nversion = \"0.1.0\"\nrequires-python = \">=3.11\"\n"
                ),
            )
            .unwrap();
        }
        fs::write(
            root.join("uv.lock"),
            r#"version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }

[package.dev-dependencies]
dev = [{ name = "mypy" }]
lint = [{ name = "black" }]

[[package]]
name = "black"
version = "24.1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "click" }]

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }
"#,
        )
        .unwrap();
        temp
    }

    /// Runs `--workspace` with `extra` args and returns member `b`'s sbom.json.
    fn member_b_sbom(temp: &TempDir, extra: &[&str]) -> String {
        let mut args = vec![
            "--workspace",
            "--path",
            temp.path().to_str().unwrap(),
            "--no-check-cve",
            "--format",
            "json",
        ];
        args.extend_from_slice(extra);
        let (exit_code, _stdout, stderr) = run_uv_sbom(&args);
        assert_eq!(exit_code, 0, "{stderr}");
        fs::read_to_string(temp.path().join("packages/b/sbom.json")).unwrap()
    }

    /// A member's SBOM lists packages from its non-`dev` groups (#997)
    #[test]
    fn test_workspace_member_sbom_includes_non_dev_group_packages() {
        let temp = rev3_workspace_with_non_dev_group();

        let sbom = member_b_sbom(&temp, &[]);
        assert!(sbom.contains("\"black\""), "lint group root must be listed");
        assert!(
            sbom.contains("\"click\""),
            "lint group subtree must be listed"
        );
        assert!(sbom.contains("\"mypy\""));
    }

    /// --exclude-groups drops a member's non-`dev` group in workspace mode (#997)
    #[test]
    fn test_workspace_exclude_groups_drops_non_dev_group_packages() {
        let temp = rev3_workspace_with_non_dev_group();

        let sbom = member_b_sbom(&temp, &["--exclude-groups", "lint"]);
        assert!(!sbom.contains("\"black\""));
        assert!(!sbom.contains("\"click\""));
        assert!(sbom.contains("\"mypy\""), "dev group is not excluded");
    }

    /// --production-only drops every group of a member in workspace mode (#997)
    #[test]
    fn test_workspace_production_only_drops_non_dev_group_packages() {
        let temp = rev3_workspace_with_non_dev_group();

        let sbom = member_b_sbom(&temp, &["--production-only"]);
        assert!(!sbom.contains("\"black\""));
        assert!(!sbom.contains("\"click\""));
        assert!(!sbom.contains("\"mypy\""));
    }
}
