/// Outbound ports (Driven ports) - Infrastructure interfaces
///
/// These ports define the interfaces that the application core uses
/// to interact with external systems (file system, network, console, etc.).
pub mod formatter;
pub mod license_repository;
pub mod lockfile_reader;
pub mod output_presenter;
pub mod progress_reporter;
pub mod project_config_reader;
pub mod vulnerability_repository;

pub use formatter::{EnrichedPackage, SbomFormatter};
pub use license_repository::{LicenseRepository, PyPiMetadata};
pub use lockfile_reader::{LockfileParseResult, LockfileReader};
pub use output_presenter::OutputPresenter;
pub use progress_reporter::ProgressReporter;
pub use project_config_reader::ProjectConfigReader;
// Note: This will be used in subsequent subtasks (Subtask 3-8)
#[allow(unused_imports)]
pub use vulnerability_repository::VulnerabilityRepository;
