/// Integration tests for the application layer
mod test_utilities;

use std::path::PathBuf;
use test_utilities::mocks::*;
use uv_sbom::prelude::*;

#[test]
fn test_generate_sbom_happy_path() {
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

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    let request = SbomRequest::new(PathBuf::from("."), false);
    let result = use_case.execute(request);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 2);
    assert!(response.dependency_graph.is_none());
}

#[test]
fn test_generate_sbom_with_dependencies() {
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

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    let request = SbomRequest::new(PathBuf::from("."), true);
    let result = use_case.execute(request);

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 3);

    // Verify dependency graph
    assert!(response.dependency_graph.is_some());
    let graph = response.dependency_graph.unwrap();
    assert_eq!(graph.direct_dependency_count(), 1);
    assert_eq!(graph.transitive_dependency_count(), 1);
}

#[test]
fn test_generate_sbom_lockfile_read_failure() {
    let lockfile_reader = MockLockfileReader::with_failure();
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    let request = SbomRequest::new(PathBuf::from("."), false);
    let result = use_case.execute(request);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("lockfile"));
}

#[test]
fn test_generate_sbom_project_config_failure() {
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

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    let request = SbomRequest::new(PathBuf::from("."), true);
    let result = use_case.execute(request);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("project config"));
}

#[test]
fn test_generate_sbom_license_repository_failure() {
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

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
    );

    let request = SbomRequest::new(PathBuf::from("."), false);
    let result = use_case.execute(request);

    // License repository failures are treated as warnings, not errors
    // The package is included without license information
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.enriched_packages.len(), 1);
    assert!(response.enriched_packages[0].license.is_none());

    // Verify that an error was reported via progress reporter
    let messages = progress_reporter.get_messages();
    assert!(messages.iter().any(|m| m.contains("Error:") && m.contains("license")));
}

#[test]
fn test_generate_sbom_invalid_toml() {
    let lockfile_content = "invalid toml content {{{";

    let lockfile_reader = MockLockfileReader::new(lockfile_content.to_string());
    let project_config_reader = MockProjectConfigReader::new("test-project".to_string());
    let license_repository = MockLicenseRepository::new();
    let progress_reporter = MockProgressReporter::new();

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
    );

    let request = SbomRequest::new(PathBuf::from("."), false);
    let result = use_case.execute(request);

    assert!(result.is_err());
}

#[test]
fn test_generate_sbom_progress_reporting() {
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
    let license_repository = MockLicenseRepository::new()
        .with_license("requests", "2.31.0", "Apache 2.0", "HTTP library");
    let progress_reporter = MockProgressReporter::new();

    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
    );

    let request = SbomRequest::new(PathBuf::from("."), false);
    let _result = use_case.execute(request);

    // Verify that progress was reported
    assert!(progress_reporter.message_count() > 0);
}
