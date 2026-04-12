/// End-to-end tests for workspace mode (--workspace flag)
mod workspace_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use std::fs;
    use tempfile::TempDir;

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
}
