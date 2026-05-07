/// End-to-end tests for the CLI
use std::path::PathBuf;
use uv_sbom::prelude::*;

// Exit code tests for CLI
mod exit_code_tests {
    use assert_cmd::cargo::cargo_bin_cmd;

    /// Exit code 0: Success - normal execution (disable CVE check to avoid network calls)
    #[test]
    fn test_exit_code_success() {
        cargo_bin_cmd!("uv-sbom")
            .args(["-p", "tests/fixtures/sample-project", "--no-check-cve"])
            .assert()
            .code(0);
    }

    /// Exit code 0: --help should return success
    #[test]
    fn test_exit_code_help() {
        cargo_bin_cmd!("uv-sbom").arg("--help").assert().code(0);
    }

    /// Exit code 0: --version should return success
    #[test]
    fn test_exit_code_version() {
        cargo_bin_cmd!("uv-sbom").arg("--version").assert().code(0);
    }

    /// Exit code 2: Invalid arguments
    #[test]
    fn test_exit_code_invalid_argument() {
        cargo_bin_cmd!("uv-sbom")
            .arg("--invalid-option")
            .assert()
            .code(2);
    }

    /// Exit code 2: Invalid format value
    #[test]
    fn test_exit_code_invalid_format() {
        cargo_bin_cmd!("uv-sbom")
            .args(["-f", "invalid_format"])
            .assert()
            .code(2);
    }

    /// Exit code 3: Application error - non-existent project path
    #[test]
    fn test_exit_code_application_error_nonexistent_path() {
        cargo_bin_cmd!("uv-sbom")
            .args(["-p", "/nonexistent/path/that/does/not/exist"])
            .assert()
            .code(3);
    }

    /// Exit code 3: Application error - path is a file, not a directory
    #[test]
    fn test_exit_code_application_error_file_not_directory() {
        cargo_bin_cmd!("uv-sbom")
            .args(["-p", "Cargo.toml"])
            .assert()
            .code(3);
    }
}

#[tokio::test]
async fn test_e2e_json_format() {
    // Use the sample project fixture
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    // Note: This test uses MockLicenseRepository to avoid network calls in tests
    // In real usage, PyPiLicenseRepository would be used
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Build read model and format as JSON
    let read_model = uv_sbom::application::read_models::SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        None,
        None,
        None,
    );
    let formatter = CycloneDxFormatter::new();
    let json_output = formatter.format(&read_model);

    assert!(json_output.is_ok());
    let json = json_output.unwrap();

    // Verify JSON structure
    assert!(json.contains("\"bomFormat\": \"CycloneDX\""));
    assert!(json.contains("\"specVersion\": \"1.6\""));
    assert!(json.contains("requests"));
    assert!(json.contains("urllib3"));
}

#[tokio::test]
async fn test_e2e_markdown_format() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Build read model and format as Markdown
    let read_model = uv_sbom::application::read_models::SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        None,
        None,
        None,
    );
    let formatter = MarkdownFormatter::new(uv_sbom::i18n::Locale::En);
    let markdown_output = formatter.format(&read_model);

    assert!(markdown_output.is_ok());
    let markdown = markdown_output.unwrap();

    // Verify Markdown structure
    assert!(markdown.contains("# Software Bill of Materials (SBOM)"));
    assert!(markdown.contains("## Component Inventory"));
    assert!(markdown.contains("## Direct Dependencies"));
    assert!(markdown.contains("## Transitive Dependencies"));
    assert!(markdown.contains("requests"));
}

#[tokio::test]
async fn test_e2e_nonexistent_project() {
    let project_path = PathBuf::from("tests/fixtures/nonexistent");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_e2e_package_count() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 5 packages: sample-project, requests, urllib3, charset-normalizer, idna, certifi
    assert_eq!(response.enriched_packages.len(), 6);

    // Verify dependency graph structure
    let graph = response
        .dependency_graph
        .expect("Dependency graph should be present");
    assert_eq!(graph.direct_dependency_count(), 1); // Only requests
    assert!(graph.transitive_dependency_count() > 0); // requests has transitive deps
}

#[tokio::test]
async fn test_e2e_exclude_single_package() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude urllib3
    let request = SbomRequest::builder()
        .project_path(project_path)
        .exclude_patterns(vec!["urllib3".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 5 packages (6 - 1 excluded)
    assert_eq!(response.enriched_packages.len(), 5);

    // Verify urllib3 is not in the result
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "urllib3"));
}

#[tokio::test]
async fn test_e2e_exclude_multiple_packages() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude urllib3 and certifi
    let request = SbomRequest::builder()
        .project_path(project_path)
        .exclude_patterns(vec!["urllib3".to_string(), "certifi".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 4 packages (6 - 2 excluded)
    assert_eq!(response.enriched_packages.len(), 4);

    // Verify excluded packages are not in the result
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "urllib3"));
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "certifi"));
}

#[tokio::test]
async fn test_e2e_exclude_with_wildcard() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude packages starting with "char"
    let request = SbomRequest::builder()
        .project_path(project_path)
        .exclude_patterns(vec!["char*".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 5 packages (charset-normalizer excluded)
    assert_eq!(response.enriched_packages.len(), 5);

    // Verify charset-normalizer is not in the result
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "charset-normalizer"));
}

#[tokio::test]
async fn test_e2e_exclude_all_packages_error() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude all packages with a pattern that matches everything
    let request = SbomRequest::builder()
        .project_path(project_path)
        .exclude_patterns(vec![
            "*requests*".to_string(),
            "*urllib3*".to_string(),
            "*charset*".to_string(),
            "*idna*".to_string(),
            "*certifi*".to_string(),
            "*sample*".to_string(),
        ])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    // Should fail because all packages would be excluded
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("All"));
    assert!(error.to_string().contains("excluded"));
}

/// Test for issue #206: Excluding root project preserves dependency classification
///
/// When the root project is excluded using the -e flag, the dependency classification
/// (direct vs transitive) should be preserved. Previously, this would result in
/// 0 direct and 0 transitive dependencies because the dependency_map was also filtered.
#[tokio::test]
async fn test_e2e_exclude_root_project_preserves_dependency_classification() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude the root project (sample-project) and request dependency info
    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .exclude_patterns(vec!["sample-project".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Root project should be excluded from packages
    // Original: sample-project, requests, urllib3, charset-normalizer, idna, certifi = 6 packages
    // After excluding sample-project: 5 packages
    assert_eq!(response.enriched_packages.len(), 5);
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "sample-project"));

    // Dependency graph should be present
    assert!(response.dependency_graph.is_some());
    let graph = response.dependency_graph.unwrap();

    // Direct dependencies should be preserved (requests is the only direct dependency)
    assert_eq!(graph.direct_dependency_count(), 1);
    assert_eq!(graph.direct_dependencies()[0].as_str(), "requests");

    // Transitive dependencies should be preserved
    // requests depends on: charset-normalizer, idna, urllib3, certifi
    assert_eq!(graph.transitive_dependency_count(), 4);
}

/// Test that excluding root project still produces valid Markdown output
#[tokio::test]
async fn test_e2e_exclude_root_project_markdown_output() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude the root project and request dependency info
    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .exclude_patterns(vec!["sample-project".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Build read model and format as Markdown
    let read_model = uv_sbom::application::read_models::SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        None,
        None,
        None,
    );
    let formatter = MarkdownFormatter::new(uv_sbom::i18n::Locale::En);
    let markdown_output = formatter.format(&read_model);

    assert!(markdown_output.is_ok());
    let markdown = markdown_output.unwrap();

    // Verify Markdown structure with dependency sections
    assert!(markdown.contains("# Software Bill of Materials (SBOM)"));
    assert!(markdown.contains("## Direct Dependencies"));
    assert!(markdown.contains("## Transitive Dependencies"));

    // Verify direct dependency is listed
    assert!(markdown.contains("requests"));

    // Verify transitive dependencies are listed
    assert!(markdown.contains("urllib3"));
    assert!(markdown.contains("certifi"));

    // Root project should NOT be in the output
    assert!(!markdown.contains("sample-project"));
}

// CLI `--lang` option tests
mod lang_option_tests {
    use assert_cmd::cargo::cargo_bin_cmd;
    use predicates::prelude::*;

    /// `--lang ja` produces Japanese section headers in stdout
    #[test]
    fn test_lang_ja_stdout_contains_japanese_section_headers() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                "tests/fixtures/sample-project",
                "-f",
                "markdown",
                "--no-check-cve",
                "--lang",
                "ja",
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("直接依存パッケージ"))
            .stdout(predicate::str::contains("コンポーネント一覧"));
    }

    /// `--lang ja` produces Japanese table column headers in stdout
    #[test]
    fn test_lang_ja_stdout_contains_japanese_column_headers() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                "tests/fixtures/sample-project",
                "-f",
                "markdown",
                "--no-check-cve",
                "--lang",
                "ja",
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("パッケージ"));
    }

    /// `--lang en` produces English section headers in stdout (regression guard)
    #[test]
    fn test_lang_en_stdout_contains_english_section_headers() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                "tests/fixtures/sample-project",
                "-f",
                "markdown",
                "--no-check-cve",
                "--lang",
                "en",
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("Direct Dependencies"))
            .stdout(predicate::str::contains("Component Inventory"));
    }

    /// `--lang en` produces English table column headers in stdout (regression guard)
    #[test]
    fn test_lang_en_stdout_contains_english_column_headers() {
        cargo_bin_cmd!("uv-sbom")
            .args([
                "-p",
                "tests/fixtures/sample-project",
                "-f",
                "markdown",
                "--no-check-cve",
                "--lang",
                "en",
            ])
            .assert()
            .code(0)
            .stdout(predicate::str::contains("Package"));
    }

    /// Invalid `--lang` value returns exit code 2 and mentions supported languages
    #[test]
    fn test_lang_invalid_value_returns_error() {
        cargo_bin_cmd!("uv-sbom")
            .args(["--lang", "fr"])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("Supported languages"));
    }
}

// Helper function to create a test license repository
// In real tests, we would use a mock to avoid network calls
fn create_test_license_repository() -> impl LicenseRepository + Clone {
    use std::collections::HashMap;

    // Type alias for license data: (license, license_expression, classifiers, description)
    type LicenseData = (Option<String>, Option<String>, Vec<String>, Option<String>);

    #[derive(Clone)]
    struct TestLicenseRepository {
        licenses: HashMap<String, LicenseData>,
    }

    impl TestLicenseRepository {
        fn new() -> Self {
            let mut licenses = HashMap::new();
            licenses.insert(
                "requests@2.31.0".to_string(),
                (
                    Some("Apache-2.0".to_string()),
                    None,
                    vec![],
                    Some("Python HTTP for Humans.".to_string()),
                ),
            );
            licenses.insert(
                "urllib3@2.1.0".to_string(),
                (
                    Some("MIT".to_string()),
                    None,
                    vec![],
                    Some("HTTP library with thread-safe connection pooling".to_string()),
                ),
            );
            licenses.insert(
                "charset-normalizer@3.3.2".to_string(),
                (
                    Some("MIT".to_string()),
                    None,
                    vec![],
                    Some("The Real First Universal Charset Detector".to_string()),
                ),
            );
            licenses.insert(
                "idna@3.6".to_string(),
                (
                    Some("BSD-3-Clause".to_string()),
                    None,
                    vec![],
                    Some("Internationalized Domain Names in Applications (IDNA)".to_string()),
                ),
            );
            licenses.insert(
                "certifi@2023.11.17".to_string(),
                (
                    Some("MPL-2.0".to_string()),
                    None,
                    vec![],
                    Some("Python package for providing Mozilla's CA Bundle.".to_string()),
                ),
            );
            Self { licenses }
        }
    }

    #[async_trait::async_trait]
    impl LicenseRepository for TestLicenseRepository {
        async fn fetch_license_info(
            &self,
            package_name: &str,
            version: &str,
        ) -> Result<(
            Option<String>,
            Option<String>,
            Vec<String>,
            Option<String>,
            Option<String>,
        )> {
            let key = format!("{}@{}", package_name, version);
            let base = self
                .licenses
                .get(&key)
                .cloned()
                .unwrap_or((None, None, vec![], None));
            Ok((base.0, base.1, base.2, base.3, None))
        }
    }

    TestLicenseRepository::new()
}
