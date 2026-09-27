/// Network adapters for external API calls
mod caching_pypi_client;
mod epss_kev_client;
mod osv_client;
mod pypi_client;
mod pypi_compatibility_client;
mod pypi_maintenance_client;

pub use caching_pypi_client::CachingPyPiLicenseRepository;
#[allow(unused_imports)] // WIRE(#878): remove when main.rs imports EpssKevClient
pub use epss_kev_client::EpssKevClient;
pub use osv_client::OsvClient;
pub use pypi_client::PyPiLicenseRepository;
pub use pypi_compatibility_client::PyPiCompatibilityClient;
pub use pypi_maintenance_client::PyPiMaintenanceRepository;
