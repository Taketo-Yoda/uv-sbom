/// End-to-end tests for incident response mode (--incident flag, #968)
mod incident_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    const SUGGEST_FIX_PROJECT: &str = "examples/suggest-fix-project";

    /// Copies `pyproject.toml` and `uv.lock` of an example project into a temp dir.
    fn copy_project(src: &str) -> TempDir {
        let temp = TempDir::new().expect("failed to create temp dir");
        for file in ["pyproject.toml", "uv.lock"] {
            fs::copy(Path::new(src).join(file), temp.path().join(file)).unwrap();
        }
        temp
    }

    /// A malformed advisory ID is an argument error (exit 2)
    #[test]
    fn test_incident_malformed_id_exits_2() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "foo", "--path", SUGGEST_FIX_PROJECT])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("Invalid advisory ID"));
    }

    /// --incident conflicts with --workspace until #969 (exit 2)
    #[test]
    fn test_incident_conflicts_with_workspace() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "CVE-2023-32681", "--workspace"])
            .assert()
            .code(2);
    }

    /// --incident conflicts with check flags that do not apply to it (exit 2)
    #[test]
    fn test_incident_conflicts_with_check_license() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "CVE-2023-32681", "--check-license"])
            .assert()
            .code(2);
    }

    /// A nonexistent project path is an application error (exit 3), before any network call
    #[test]
    fn test_incident_invalid_project_path_exits_3() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--path",
                "/nonexistent/uv-sbom-incident-test",
            ])
            .assert()
            .code(3);
    }

    /// Affected with a released fix: Markdown by default, verified command, exit 1
    #[test]
    #[ignore = "requires network access to OSV and PyPI, and uv on PATH"]
    fn test_incident_affected_fix_released_exits_1() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "GHSA-v845-jxx5-vc9f",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .stdout(predicate::str::contains(
                "## Incident Report: GHSA-v845-jxx5-vc9f",
            ))
            .stdout(predicate::str::contains(
                "uv lock --upgrade-package urllib3==2.0.6",
            ));
    }

    /// A CVE ID resolves to its GHSA record; not affected exits 0
    #[test]
    #[ignore = "requires network access to OSV and PyPI"]
    fn test_incident_not_affected_via_cve_alias_exits_0() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("(resolved from CVE-2023-32681)"));
    }

    /// An unknown advisory ID prints a localized error and exits 3
    #[test]
    #[ignore = "requires network access to OSV"]
    fn test_incident_unknown_advisory_exits_3_localized() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "GHSA-xxxx-xxxx-xxxx",
                "--lang",
                "ja",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(3)
            .stderr(predicate::str::contains(
                "アドバイザリ GHSA-xxxx-xxxx-xxxx は OSV データベースに見つかりませんでした",
            ));
    }

    /// The config file's `format: json` does not change incident output
    #[test]
    #[ignore = "requires network access to OSV and PyPI"]
    fn test_incident_ignores_config_format() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);
        fs::write(temp.path().join("uv-sbom.config.yml"), "format: json\n").unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::starts_with("## Incident Report:"));
    }

    /// --format json produces JSON
    #[test]
    #[ignore = "requires network access to OSV and PyPI"]
    fn test_incident_format_json() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--format",
                "json",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["overall"], "not_affected");
    }
}
