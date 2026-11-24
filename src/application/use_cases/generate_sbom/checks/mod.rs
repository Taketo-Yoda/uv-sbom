mod abandoned;
mod license;
mod non_pypi;
mod python_compat;
mod views;
mod vulnerabilities;
mod yanked;

use super::GenerateSbomUseCase;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
    YankedStatusRepository,
};
use crate::sbom_generation::domain::{DependencyGraph, UvLockSimulator};
use std::collections::HashSet;

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository + Clone,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository + Clone,
    MREPO: MaintenanceRepository + Clone,
    PCREPO: PythonCompatibilityRepository + Clone,
    USIM: UvLockSimulator,
    EREPO: ExploitabilityRepository,
    YREPO: YankedStatusRepository + Clone,
{
    /// Returns the set of direct dependency names from the graph.
    ///
    /// When `dependency_graph` is `None`, returns an empty set so every package
    /// is treated as transitive — consistent across all `check_*_if_requested` methods.
    fn resolve_direct_names(dependency_graph: Option<&DependencyGraph>) -> HashSet<&str> {
        dependency_graph
            .map(|g| g.direct_dependencies().iter().map(|p| p.as_str()).collect())
            .unwrap_or_default()
    }
}
