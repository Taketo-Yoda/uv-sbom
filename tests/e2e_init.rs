/// End-to-end tests for the --init CLI option
mod init_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use std::fs;
    use tempfile::TempDir;

    const CONFIG_FILENAME: &str = "uv-sbom.config.yml";

    /// --init creates a config template file in the current directory
    #[test]
    fn test_init_creates_config_file() {
        let dir = TempDir::new().unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args(["--init", "--path", dir.path().to_str().unwrap()])
            .assert()
            .code(0);

        let config_path = dir.path().join(CONFIG_FILENAME);
        assert!(config_path.exists(), "Config file should be created");

        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("uv-sbom configuration file"));
        assert!(content.contains("format: json"));
        assert!(content.contains("exclude_packages:"));
        assert!(content.contains("check_cve:"));
        assert!(content.contains("severity_threshold:"));
        assert!(content.contains("cvss_threshold:"));
        assert!(content.contains("ignore_cves:"));
    }

    /// --init fails with non-zero exit when config file already exists
    #[test]
    fn test_init_fails_if_config_exists() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(CONFIG_FILENAME);
        fs::write(&config_path, "existing content").unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args(["--init", "--path", dir.path().to_str().unwrap()])
            .assert()
            .code(3)
            .stderr(predicates::str::contains("already exists"));
    }

    /// --init with --path writes to the specified directory
    #[test]
    fn test_init_with_path_option() {
        let dir = TempDir::new().unwrap();
        let sub_dir = dir.path().join("sub");
        fs::create_dir(&sub_dir).unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args(["--init", "--path", sub_dir.to_str().unwrap()])
            .assert()
            .code(0)
            .stderr(predicates::str::contains("Created"));

        let config_path = sub_dir.join(CONFIG_FILENAME);
        assert!(
            config_path.exists(),
            "Config file should be created in sub directory"
        );
    }

    /// --init prints confirmation message with path
    #[test]
    fn test_init_prints_confirmation() {
        let dir = TempDir::new().unwrap();

        cargo_bin_cmd!("uv-sbom")
            .args(["--init", "--path", dir.path().to_str().unwrap()])
            .assert()
            .code(0)
            .stderr(predicates::str::contains("Created uv-sbom.config.yml"));
    }
}
