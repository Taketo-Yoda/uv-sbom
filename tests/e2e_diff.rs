/// End-to-end tests for dependency diff mode (--diff flag)
mod diff_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use std::fs;
    use tempfile::TempDir;

    /// Copies the "after" fixture lockfile into a temp directory as `uv.lock`.
    /// Returns (temp_dir, abs_path_to_before_lock).
    fn setup_diff_temp() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().expect("failed to create temp dir");
        let after_lock = std::path::Path::new("tests/fixtures/sample_uv_lock_after.lock");
        let before_lock =
            std::path::Path::new("tests/fixtures/sample_uv_lock_before.lock").canonicalize().expect("before lock must exist");

        fs::copy(after_lock, temp.path().join("uv.lock")).unwrap();

        (temp, before_lock)
    }

    /// --diff with a file path produces JSON output (exit 0)
    #[test]
    fn test_diff_with_file_path_json() {
        let (temp, before_lock) = setup_diff_temp();

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                before_lock.to_str().unwrap(),
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
                "--format",
                "json",
            ])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value =
            serde_json::from_slice(&output).expect("stdout must be valid JSON");

        assert!(json["diff"].is_object(), "top-level key 'diff' must exist");
        assert!(
            json["diff"]["base"].is_string(),
            "'diff.base' must be a string"
        );
        assert!(json["diff"]["summary"].is_object());
        assert!(json["diff"]["changes"].is_array());

        // before has certifi@2022.12.7, requests@2.31.0, urllib3@1.26.5
        // after has certifi@2024.2.2, requests@2.32.3, urllib3@2.2.1 — all 3 updated
        assert_eq!(json["diff"]["summary"]["updated"], 3);
        assert_eq!(json["diff"]["summary"]["added"], 0);
        assert_eq!(json["diff"]["summary"]["removed"], 0);
    }

    /// --diff with a file path produces Markdown output (exit 0)
    #[test]
    fn test_diff_with_file_path_markdown() {
        let (temp, before_lock) = setup_diff_temp();

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                before_lock.to_str().unwrap(),
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
                "--format",
                "markdown",
            ])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();

        let md = String::from_utf8(output).expect("stdout must be UTF-8");
        assert!(
            md.contains("## Dependency Diff Report"),
            "Markdown must contain the report header"
        );
        assert!(
            md.contains("Compared:"),
            "Markdown must contain the 'Compared:' line"
        );
        assert!(md.contains("### Summary"));
        assert!(md.contains("### Changes"));
    }

    /// --diff with --output writes to a file instead of stdout
    #[test]
    fn test_diff_to_output_file() {
        let (temp, before_lock) = setup_diff_temp();
        let output_file = temp.path().join("diff.json");

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                before_lock.to_str().unwrap(),
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
                "--format",
                "json",
                "--output",
                output_file.to_str().unwrap(),
            ])
            .assert()
            .code(0);

        assert!(output_file.exists(), "output file must be created");
        let content = fs::read_to_string(&output_file).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&content).expect("output file must be valid JSON");
        assert!(json["diff"].is_object());
    }

    /// --diff conflicts with --workspace (exit 2)
    #[test]
    fn test_diff_conflicts_with_workspace() {
        let temp = TempDir::new().unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                "main",
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(2);
    }

    /// --diff conflicts with --init (exit 2)
    #[test]
    fn test_diff_conflicts_with_init() {
        let temp = TempDir::new().unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                "main",
                "--init",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(2);
    }

    /// --diff with an invalid git ref containing a semicolon is rejected (exit 3)
    #[test]
    fn test_diff_invalid_git_ref_rejected_by_security_validator() {
        let (temp, _) = setup_diff_temp();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--diff",
                "main;rm -rf /",
                "--path",
                temp.path().to_str().unwrap(),
                "--no-check-cve",
            ])
            .assert()
            .code(3);
    }
}
