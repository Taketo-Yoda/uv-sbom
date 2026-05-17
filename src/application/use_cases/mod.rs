/// Use cases module containing application business logic orchestration
mod check_abandoned_packages;
mod check_vulnerabilities;
mod fetch_licenses;
mod generate_diff;
mod generate_sbom;

#[cfg(test)]
pub(crate) mod test_doubles;

pub use check_abandoned_packages::CheckAbandonedPackagesUseCase;
pub use check_vulnerabilities::CheckVulnerabilitiesUseCase;
pub use fetch_licenses::FetchLicensesUseCase;
// Note: Will be wired to the binary in a subsequent CLI integration subtask of #224.
#[allow(unused_imports)]
pub use generate_diff::GenerateDiffUseCase;
pub use generate_sbom::GenerateSbomUseCase;
