/// End-to-end tests for incident response mode (--incident flag, #968; --workspace, #969;
/// manual range specs, #963)
mod incident_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    const SUGGEST_FIX_PROJECT: &str = "examples/suggest-fix-project";
    const SAMPLE_PROJECT: &str = "examples/sample-project";
    const WORKSPACE_PROJECT: &str = "examples/workspace";

    /// Copies `pyproject.toml` and `uv.lock` of an example project into a temp dir.
    fn copy_project(src: &str) -> TempDir {
        let temp = TempDir::new().expect("failed to create temp dir");
        for file in ["pyproject.toml", "uv.lock"] {
            fs::copy(Path::new(src).join(file), temp.path().join(file)).unwrap();
        }
        temp
    }

    /// Copies the example workspace's root files and member `pyproject.toml`
    /// files (no committed `sbom.*` outputs) into a temp dir.
    fn copy_workspace() -> TempDir {
        let temp = copy_project(WORKSPACE_PROJECT);
        for member in ["packages/api", "packages/worker"] {
            fs::create_dir_all(temp.path().join(member)).unwrap();
            fs::copy(
                Path::new(WORKSPACE_PROJECT)
                    .join(member)
                    .join("pyproject.toml"),
                temp.path().join(member).join("pyproject.toml"),
            )
            .unwrap();
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

    /// --incident --workspace still rejects --output, via --workspace (exit 2)
    #[test]
    fn test_incident_workspace_conflicts_with_output() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--workspace",
                "-o",
                "report.md",
            ])
            .assert()
            .code(2);
    }

    /// --incident --workspace with a nonexistent root is an application error (exit 3)
    #[test]
    fn test_incident_workspace_invalid_path_exits_3() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "CVE-2023-32681",
                "--workspace",
                "--path",
                "/nonexistent/uv-sbom-incident-test",
            ])
            .assert()
            .code(3);
    }

    /// One combined workspace report: only `api` reaches starlette, the
    /// aggregate exit code is 1, and no per-member sbom file is written
    #[test]
    #[ignore = "requires network access to OSV and PyPI, and uv on PATH"]
    fn test_incident_workspace_reports_per_member_and_writes_no_files() {
        let temp = copy_workspace();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "GHSA-82w8-qh3p-5jfq",
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("#### Member: api"))
            .stdout(predicate::str::contains("#### Member: worker"))
            .stdout(predicate::str::contains("`fastapi → starlette`"))
            .stdout(predicate::str::contains("**1 of 2 members affected**: api"));

        for member in ["packages/api", "packages/worker"] {
            for ext in ["json", "md"] {
                assert!(!temp
                    .path()
                    .join(member)
                    .join(format!("sbom.{ext}"))
                    .exists());
            }
        }
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

    // ---- manual range specs (#963) ----

    /// Unsupported operators and a bare name are argument errors (exit 2)
    #[test]
    fn test_incident_manual_spec_rejections_exit_2() {
        for (spec, reason) in [
            (
                "requests==2.25.0",
                "'==2.25.0' uses an unsupported operator",
            ),
            ("requests", "No version range was given for 'requests'."),
            ("requests>2.0", "'>2.0' uses an unsupported operator"),
            ("requests>=2.3,<2.0", "contains no versions"),
        ] {
            cargo_bin_cmd!("uv-sbom")
                .args(["--incident", spec, "--path", SAMPLE_PROJECT])
                .assert()
                .code(2)
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::contains(format!(
                    "Invalid advisory ID or version-range spec: '{spec}'."
                )))
                .stderr(predicate::str::contains(reason));
        }
    }

    /// A rejected spec is reported in the --lang locale
    #[test]
    fn test_incident_manual_spec_rejection_localized_ja() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "requests>2.0", "--lang", "ja"])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(
                "アドバイザリ ID またはバージョン範囲の指定が不正です: 'requests>2.0'。",
            ));
    }

    /// Outside the supplied range: not affected, exit 0. No fixed version
    /// means no PyPI or OSV request, so this runs offline.
    #[test]
    fn test_incident_manual_spec_not_affected_exits_0() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "requests>=2.26,<2.31.0",
                "--path",
                SAMPLE_PROJECT,
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains(
                "## Incident Report (manual range): `requests>=2.26,<2.31.0`",
            ))
            .stdout(predicate::str::contains(
                "not taken from a vulnerability database",
            ))
            .stdout(predicate::str::contains("Not affected"));
    }

    /// `<=` names no fix: affected, no command, exit 4 (offline)
    #[test]
    fn test_incident_manual_spec_last_affected_exits_4() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "requests<=2.30.0", "--path", SAMPLE_PROJECT])
            .assert()
            .code(4)
            .stdout(predicate::str::contains("Affected — no fix available"))
            .stdout(predicate::str::contains(
                "the supplied range names no fixed version",
            ))
            .stdout(predicate::str::contains("uv lock").not());
    }

    /// JSON output marks the source as manual (offline)
    #[test]
    fn test_incident_manual_spec_format_json() {
        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "requests<=2.30.0",
                "--path",
                SAMPLE_PROJECT,
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["source"], "manual");
        assert_eq!(value["advisory_id"], "requests<=2.30.0");
        assert_eq!(value["overall"], "affected_no_fix");
    }

    /// A fixed version that is not on PyPI: fix not yet released, exit 4
    #[test]
    #[ignore = "requires network access to PyPI"]
    fn test_incident_manual_spec_unreleased_fix_exits_4() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--incident", "requests<9999.0", "--path", SAMPLE_PROJECT])
            .assert()
            .code(4)
            .stdout(predicate::str::contains(
                "fixed in 9999.0 — not published on PyPI",
            ));
    }

    /// Affected with a released fix on an exact pin: exit 1, resolution blocked
    #[test]
    #[ignore = "requires network access to PyPI, and uv on PATH"]
    fn test_incident_manual_spec_pinned_fix_released_exits_1() {
        let temp = copy_project(SAMPLE_PROJECT);

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "requests<2.31.0",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("fixed in 2.31.0 — released"))
            .stdout(predicate::str::contains("could not be resolved"));
    }

    /// Affected with a released fix: verified command, exit 1
    #[test]
    #[ignore = "requires network access to PyPI, and uv on PATH"]
    fn test_incident_manual_spec_verified_command_exits_1() {
        let temp = copy_project(SUGGEST_FIX_PROJECT);

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "urllib3<2.0.6",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .stdout(predicate::str::contains("`requests → urllib3`"))
            .stdout(predicate::str::contains(
                "uv lock --upgrade-package urllib3==2.0.6",
            ));
    }

    /// --workspace with a manual spec: one combined report (offline for `<=`)
    #[test]
    fn test_incident_manual_spec_workspace_exits_4() {
        let temp = copy_workspace();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "starlette<=1.0.0",
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(4)
            .stdout(predicate::str::contains(
                "## Incident Report (manual range): `starlette<=1.0.0`",
            ))
            .stdout(predicate::str::contains("**1 of 2 members affected**: api"));
    }

    /// Writes a revision-3 workspace (no `[manifest.dependency-groups]`) where
    /// member `a`, which sorts first, declares no `dev` group (only
    /// `lint = [black]`), and member `b` declares `dev = [ruff]`. Covers both the
    /// later-member `dev` group (#995) and `a`'s non-`dev` group (#997).
    fn rev3_workspace_with_dev_only_in_later_member() -> TempDir {
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

[package.dev-dependencies]
lint = [{ name = "black" }]

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }

[package.dev-dependencies]
dev = [{ name = "ruff" }]

[[package]]
name = "black"
version = "24.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "ruff"
version = "0.3.0"
source = { registry = "https://pypi.org/simple" }
"#,
        )
        .unwrap();
        temp
    }

    /// --production-only in a revision-3 workspace excludes the `dev` group
    /// even when only a later member declares it (#995). Offline: `<=` names
    /// no fixed version.
    #[test]
    fn test_incident_workspace_production_only_excludes_group_of_later_member() {
        let temp = rev3_workspace_with_dev_only_in_later_member();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "ruff<=99.0",
                "--workspace",
                "--production-only",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("**0 of 2 members affected**"));
    }

    /// Without --production-only the same workspace reports `b` as affected,
    /// so the test above is not passing vacuously.
    #[test]
    fn test_incident_workspace_later_member_dev_group_is_affected_without_production_only() {
        let temp = rev3_workspace_with_dev_only_in_later_member();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "ruff<=99.0",
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(4)
            .stdout(predicate::str::contains("**1 of 2 members affected**: b"));
    }

    /// A member's non-`dev` group packages are evaluated (#997): `a` reaches
    /// `black` only through its `lint` group. Offline: `<=` names no fixed version.
    #[test]
    fn test_incident_workspace_member_non_dev_group_is_affected() {
        let temp = rev3_workspace_with_dev_only_in_later_member();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "black<=99.0",
                "--workspace",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(4)
            .stdout(predicate::str::contains("**1 of 2 members affected**: a"));
    }

    /// --exclude-groups drops the member's non-`dev` group in incident mode (#997)
    #[test]
    fn test_incident_workspace_exclude_non_dev_group_is_not_affected() {
        let temp = rev3_workspace_with_dev_only_in_later_member();

        cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "black<=99.0",
                "--workspace",
                "--exclude-groups",
                "lint",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("**0 of 2 members affected**"));
    }

    /// Dependency paths stay runtime-only (#997): `black` is reached only through
    /// `a`'s `lint` group, so it is neither direct nor on any `a → black` path.
    #[test]
    fn test_incident_workspace_group_package_paths_stay_runtime_only() {
        let temp = rev3_workspace_with_dev_only_in_later_member();

        let output = cargo_bin_cmd!("uv-sbom")
            .args([
                "--incident",
                "black<=99.0",
                "--workspace",
                "--format",
                "json",
                "--path",
                temp.path().to_str().unwrap(),
            ])
            .assert()
            .code(4)
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let member_a = json["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == "a")
            .expect("member a must be reported");
        let finding = &member_a["findings"][0];
        assert_eq!(finding["package_name"], "black");
        assert_eq!(finding["is_direct"], false);
        assert_eq!(finding["paths"], serde_json::json!([]));
    }
}
