/// Integration tests for the application layer
mod test_utilities;

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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder().project_path(".").build().unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(".")
        .include_dependency_info(true)
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder().project_path(".").build().unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(".")
        .include_dependency_info(true)
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder().project_path(".").build().unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder().project_path(".").build().unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter.clone(),
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder().project_path(".").build().unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude urllib3
    let request = SbomRequest::builder()
        .project_path(".")
        .exclude_patterns(vec!["urllib3".to_string()])
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude urllib3 and certifi
    let request = SbomRequest::builder()
        .project_path(".")
        .exclude_patterns(vec!["urllib3".to_string(), "certifi".to_string()])
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude all pytest-related packages
    let request = SbomRequest::builder()
        .project_path(".")
        .exclude_patterns(vec!["pytest*".to_string()])
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude all packages with a pattern that matches everything
    let request = SbomRequest::builder()
        .project_path(".")
        .exclude_patterns(vec!["*requests*".to_string()])
        .build()
        .unwrap();
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

    let use_case: GenerateSbomUseCase<_, _, _, _, (), (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    // Exclude urllib3 and request dependency graph
    let request = SbomRequest::builder()
        .project_path(".")
        .include_dependency_info(true)
        .exclude_patterns(vec!["urllib3".to_string()])
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok());
    let response = result.unwrap();

    // Should have 2 packages (myproject + requests, urllib3 excluded from package list)
    assert_eq!(response.enriched_packages.len(), 2);

    // Verify dependency graph exists
    assert!(response.dependency_graph.is_some());
    let graph = response.dependency_graph.unwrap();

    // requests should still be a direct dependency
    assert_eq!(graph.direct_dependency_count(), 1);

    // urllib3 is still counted as a transitive dependency in the graph
    // (dependency classification is preserved even when packages are excluded)
    // This is expected behavior per issue #206 - exclusion filters packages
    // but preserves dependency_map for correct direct/transitive classification
    assert_eq!(graph.transitive_dependency_count(), 1);
}

// Regression tests for #1042: OSV malicious-package advisories (`MAL-`) must
// exceed any threshold and must not be suppressed by a baseline.

const SINGLE_PACKAGE_LOCKFILE: &str = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "evil-pkg"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"#;

fn unscored_vulnerability(id: &str) -> uv_sbom::sbom_generation::domain::Vulnerability {
    use uv_sbom::sbom_generation::domain::{Severity, Vulnerability};
    Vulnerability::new(id.to_string(), None, Severity::None, None, None, vec![]).unwrap()
}

async fn execute_with_findings(
    vulnerability_id: &str,
    baseline: Option<uv_sbom::sbom_generation::domain::VulnerabilityBaseline>,
) -> SbomResponse {
    use uv_sbom::sbom_generation::domain::{PackageVulnerabilities, Severity};

    let findings = vec![PackageVulnerabilities::new(
        "evil-pkg".to_string(),
        "1.0.0".to_string(),
        vec![unscored_vulnerability(vulnerability_id)],
    )];

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository, (), ()> =
        GenerateSbomUseCase::new(
            MockLockfileReader::new(SINGLE_PACKAGE_LOCKFILE.to_string()),
            MockProjectConfigReader::new("test-project".to_string()),
            MockLicenseRepository::new(),
            MockProgressReporter::new(),
            Some(MockVulnerabilityRepository::new(findings)),
            None,
            None,
            None,
            None,
            uv_sbom::i18n::Locale::En,
        );

    let request = SbomRequest::builder()
        .project_path(".")
        .check_cve(true)
        .severity_threshold_opt(Some(Severity::Low))
        .baseline(baseline)
        .build()
        .unwrap();

    use_case.execute(request).await.unwrap()
}

#[tokio::test]
async fn test_malicious_advisory_exceeds_severity_threshold() {
    let response = execute_with_findings("MAL-2024-0001", None).await;

    assert!(response.has_vulnerabilities_above_threshold);
    let result = response.vulnerability_check_result.unwrap();
    assert!(result.threshold_exceeded);
    assert_eq!(
        result.above_threshold[0].vulnerabilities()[0].id(),
        "MAL-2024-0001"
    );
}

#[tokio::test]
async fn test_unscored_non_malicious_advisory_stays_below_threshold() {
    let response = execute_with_findings("GHSA-xxxx-yyyy-zzzz", None).await;

    assert!(!response.has_vulnerabilities_above_threshold);
    let result = response.vulnerability_check_result.unwrap();
    assert!(!result.threshold_exceeded);
    assert!(result.above_threshold.is_empty());
    assert_eq!(
        result.below_threshold[0].vulnerabilities()[0].id(),
        "GHSA-xxxx-yyyy-zzzz"
    );
}

#[tokio::test]
async fn test_malicious_advisory_not_suppressed_by_baseline() {
    use uv_sbom::sbom_generation::domain::{BaselineEntry, VulnerabilityBaseline};

    let baseline = VulnerabilityBaseline::from_entries(vec![BaselineEntry {
        package: "evil-pkg".to_string(),
        version: "1.0.0".to_string(),
        id: "MAL-2024-0001".to_string(),
    }]);
    let response = execute_with_findings("MAL-2024-0001", Some(baseline)).await;

    assert!(response.has_vulnerabilities_above_threshold);
    assert_eq!(response.baseline_suppressed_count, 0);
}
