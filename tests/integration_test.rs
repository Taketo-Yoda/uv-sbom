/// Integration tests for the application layer
mod test_utilities;

use std::path::PathBuf;
use test_utilities::mocks::*;
use uv_sbom::prelude::*;

#[tokio::test]
async fn test_generate_sbom_happy_path() {
    // Setup mock data
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new()
        .with_license("requests", "2.31.0", "Apache 2.0", "HTTP library")
        .with_license("urllib3", "1.26.0", "MIT", "HTTP library");
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), false, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 2);
    assert!(response.dependency_graph.is_none());
}

#[tokio::test]
async fn test_generate_sbom_with_dependencies() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "myproject"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("myproject".to_string());
    let license_repository = MockLicenseRepository::new()
        .with_license("requests", "2.31.0", "Apache 2.0", "HTTP library")
        .with_license("urllib3", "1.26.0", "MIT", "HTTP library");
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), true, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 3);

    // Verify dependency graph
    assert!(response.dependency_graph.is_some());
    let graph = response.dependency_graph.unwrap();
    assert_eq!(graph.direct_dependency_count(), 1);
    assert_eq!(graph.transitive_dependency_count(), 1);
}

#[tokio::test]
async fn test_generate_sbom_lockfile_read_failure() {
    let lockfile_reader = MockLockfileReader::with_failure();
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), false, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("lockfile"));
}

#[tokio::test]
async fn test_generate_sbom_project_config_failure() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::with_failure();
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), true, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("project config"));
}

#[tokio::test]
async fn test_generate_sbom_license_repository_failure() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::with_failure();
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), false, vec![], false, false);
    let result = use_case.execute(request).await;

    // License repository failures are treated as warnings, not errors
    // The package is included without license information
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 1);
    assert!(response.enriched_packages[0].license.is_none());

    // Verify that an error was reported via progress reporter
    let messages = progress_reporter.get_messages();
    assert!(messages
        .iter()
        .any(|m| m.contains("Error:") && m.contains("license")));
}

#[tokio::test]
async fn test_generate_sbom_invalid_toml() {
    let lockfile_content = "invalid toml content {{{";

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), false, vec![], false, false);
    let result = use_case.execute(request).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_generate_sbom_progress_reporting() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new().with_license(
        "requests",
        "2.31.0",
        "Apache 2.0",
        "HTTP library",
    );
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
        None,
    );

    let request = SbomRequest::new(PathBuf::from("."), false, vec![], false, false);
    let _result = use_case.execute(request).await;

    // Verify that progress was reported
    assert!(progress_reporter.message_count() > 0);
}

#[tokio::test]
async fn test_generate_sbom_exclude_single_package() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "certifi"
version = "2023.11.17"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new()
        .with_license("requests", "2.31.0", "Apache 2.0", "HTTP library")
        .with_license("urllib3", "1.26.0", "MIT", "HTTP library")
        .with_license("certifi", "2023.11.17", "MPL-2.0", "CA Bundle");
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude urllib3
    let request = SbomRequest::new(
        PathBuf::from("."),
        false,
        vec!["urllib3".to_string()],
        false,
        false,
    );
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 2 packages (3 - 1 excluded)
    assert_eq!(response.enriched_packages.len(), 2);

    // Verify urllib3 is not in the result
    assert!(!response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "urllib3"));

    // Verify other packages are present
    assert!(response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "requests"));
    assert!(response
        .enriched_packages
        .iter()
        .any(|p| p.package.name() == "certifi"));
}

#[tokio::test]
async fn test_generate_sbom_exclude_multiple_packages() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "certifi"
version = "2023.11.17"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new().with_license(
        "requests",
        "2.31.0",
        "Apache 2.0",
        "HTTP library",
    );
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude urllib3 and certifi
    let request = SbomRequest::new(
        PathBuf::from("."),
        false,
        vec!["urllib3".to_string(), "certifi".to_string()],
        false,
        false,
    );
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 1 package (3 - 2 excluded)
    assert_eq!(response.enriched_packages.len(), 1);
    assert_eq!(response.enriched_packages[0].package.name(), "requests");
}

#[tokio::test]
async fn test_generate_sbom_exclude_with_wildcard() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest-cov"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new().with_license(
        "requests",
        "2.31.0",
        "Apache 2.0",
        "HTTP library",
    );
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude all pytest-related packages
    let request = SbomRequest::new(
        PathBuf::from("."),
        false,
        vec!["pytest*".to_string()],
        false,
        false,
    );
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 1 package (pytest and pytest-cov excluded)
    assert_eq!(response.enriched_packages.len(), 1);
    assert_eq!(response.enriched_packages[0].package.name(), "requests");
}

#[tokio::test]
async fn test_generate_sbom_exclude_all_packages_error() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude all packages with a pattern that matches everything
    let request = SbomRequest::new(
        PathBuf::from("."),
        false,
        vec!["*requests*".to_string()],
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

#[tokio::test]
async fn test_generate_sbom_exclude_with_dependency_graph() {
    let lockfile_content = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "myproject"
version = "1.0.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }
"#;

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("myproject".to_string());
    let license_repository = MockLicenseRepository::new().with_license(
        "requests",
        "2.31.0",
        "Apache 2.0",
        "HTTP library",
    );
    let progress_reporter = MockProgressReporter::new();

    let use_case: GenerateSbomUseCase<_, _, _, _, ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
    );

    // Exclude urllib3 and request dependency graph
    let request = SbomRequest::new(
        PathBuf::from("."),
        true,
        vec!["urllib3".to_string()],
        false,
        false,
    );
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 2 packages (myproject + requests, urllib3 excluded)
    assert_eq!(response.enriched_packages.len(), 2);

    // Verify dependency graph exists but urllib3 is not in it
    assert!(response.dependency_graph.is_some());
    let graph = response.dependency_graph.unwrap();

    // requests should still be a direct dependency
    assert_eq!(graph.direct_dependency_count(), 1);

    // urllib3 should not be in transitive dependencies (it was excluded)
    assert_eq!(graph.transitive_dependency_count(), 0);
}
