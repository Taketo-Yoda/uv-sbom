/// Network adapters for external API calls
mod caching_pypi_client;
mod osv_client;
mod pypi_client;

pub use caching_pypi_client::CachingPyPiLicenseRepository;
// Note: This will be used in subsequent subtasks for CVE check feature
#[allow(unused_imports)]
pub use osv_client::OsvClient;
pub use pypi_client::PyPiLicenseRepository;
