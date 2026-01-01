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

pub use formatter::{EnrichedPackage, SbomFormatter};
pub use license_repository::LicenseRepository;
pub use lockfile_reader::LockfileReader;
pub use output_presenter::OutputPresenter;
pub use progress_reporter::ProgressReporter;
pub use project_config_reader::ProjectConfigReader;
