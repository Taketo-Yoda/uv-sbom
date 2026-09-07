/// Outbound ports (Driven ports) - Infrastructure interfaces
///
/// These ports define the interfaces that the application core uses
/// to interact with external systems (file system, network, console, etc.).
pub mod diff_lockfile_reader;
pub mod formatter;
pub mod license_repository;
pub mod lockfile_reader;
pub mod maintenance_repository;
pub mod output_presenter;
pub mod progress_reporter;
pub mod project_config_reader;
pub mod python_compatibility_repository;
pub mod vulnerability_repository;
pub mod workspace_reader;

// `EnrichedPackage`, `UvLockSimulator` / `SimulationResult` are defined in
// `crate::sbom_generation::domain`, not here: `ResolutionAnalyzer` consumes
// `EnrichedPackage` directly, and the domain layer must not import from
// `ports/`. `UvLockSimulator` was originally placed alongside it because
// `UpgradeAdvisor` consumed it as a generic bound (#703); as of #716,
// `UpgradeAdvisor` is a pure comparator and no longer does, but the trait
// remains here rather than moving to `ports/outbound/` (see doc comment on
// `sbom_generation::domain::uv_lock_simulator`). It is implemented by
// `adapters::outbound::uv::UvLockAdapter`.

pub use diff_lockfile_reader::{DiffLockfileReader, DiffSource};
pub use formatter::SbomFormatter;
pub use license_repository::{LicenseRepository, PyPiMetadata};
pub use lockfile_reader::{
    GroupRoots, LockfileParseResult, LockfileReader, PackageSourceKind, PackageSourceMap,
};
// Note: Will be used in subsequent subtasks (abandoned package detection)
#[allow(unused_imports)]
pub use maintenance_repository::{MaintenanceInfo, MaintenanceRepository};
pub use output_presenter::OutputPresenter;
pub use progress_reporter::{ProgressCallback, ProgressReporter};
pub use project_config_reader::ProjectConfigReader;
pub use python_compatibility_repository::{PythonCompatibilityInfo, PythonCompatibilityRepository};
// Note: This will be used in subsequent subtasks (Subtask 3-8)
#[allow(unused_imports)]
pub use vulnerability_repository::VulnerabilityRepository;
// Note: Will be used in a subsequent subtask for workspace detection
#[allow(unused_imports)]
pub use workspace_reader::{WorkspaceMember, WorkspaceReader};
