/// End-to-end tests for the CLI
use std::path::PathBuf;
use uv_sbom::prelude::*;

#[tokio::test]
async fn test_e2e_json_format() {
    // Use the sample project fixture
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    // Note: This test uses MockLicenseRepository to avoid network calls in tests
    // In real usage, PyPiLicenseRepository would be used
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(project_path, false, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Format as JSON
    let formatter = CycloneDxFormatter::new();
    let json_output = formatter.format(response.enriched_packages, &response.metadata, None);

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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(project_path, true, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Format as Markdown
    let formatter = MarkdownFormatter::new();
    let markdown_output = formatter.format_with_dependencies(
        &response
            .dependency_graph
            .expect("Dependency graph should be present"),
        response.enriched_packages,
        &response.metadata,
        None,
    );

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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(project_path, false, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_e2e_package_count() {
    let project_path = PathBuf::from("tests/fixtures/sample-project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(project_path, true, vec![], false, false);
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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude urllib3
    let request = SbomRequest::new(
        project_path,
        false,
        vec!["urllib3".to_string()],
        false,
        false,
    );
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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude urllib3 and certifi
    let request = SbomRequest::new(
        project_path,
        false,
        vec!["urllib3".to_string(), "certifi".to_string()],
        false,
        false,
    );
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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude packages starting with "char"
    let request = SbomRequest::new(project_path, false, vec!["char*".to_string()], false, false);
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
    let progress_reporter = StderrProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude all packages with a pattern that matches everything
    let request = SbomRequest::new(
        project_path,
        false,
        vec![
            "*requests*".to_string(),
            "*urllib3*".to_string(),
            "*charset*".to_string(),
            "*idna*".to_string(),
            "*certifi*".to_string(),
            "*sample*".to_string(),
        ],
        false,
        false,
    );
    let result = use_case.execute(request).await;

    // Should fail because all packages would be excluded
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("All"));
    assert!(error.to_string().contains("excluded"));
}

// Helper function to create a test license repository
// In real tests, we would use a mock to avoid network calls
fn create_test_license_repository() -> impl LicenseRepository {
    use std::collections::HashMap;

    // Type alias for license data: (license, license_expression, classifiers, description)
    type LicenseData = (Option<String>, Option<String>, Vec<String>, Option<String>);

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
        ) -> Result<(Option<String>, Option<String>, Vec<String>, Option<String>)> {
            let key = format!("{}@{}", package_name, version);
            Ok(self
                .licenses
                .get(&key)
                .cloned()
                .unwrap_or((None, None, vec![], None)))
        }
    }

    TestLicenseRepository::new()
}
