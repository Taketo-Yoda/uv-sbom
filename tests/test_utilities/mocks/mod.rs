/// Mock implementations for testing
mod mock_license_repository;
mod mock_lockfile_reader;
mod mock_progress_reporter;
mod mock_project_config_reader;

pub use mock_license_repository::MockLicenseRepository;
pub use mock_lockfile_reader::MockLockfileReader;
pub use mock_progress_reporter::MockProgressReporter;
pub use mock_project_config_reader::MockProjectConfigReader;
