use serde::Deserialize;

/// FIRST.org EPSS API response
#[derive(Debug, Deserialize)]
pub(super) struct EpssApiResponse {
    #[serde(default)]
    pub data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
pub(super) struct EpssEntry {
    pub cve: String,
    pub epss: String,
    pub percentile: String,
}

/// CISA KEV catalog response
#[derive(Debug, Deserialize)]
pub(super) struct KevCatalogResponse {
    #[serde(default)]
    pub vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
pub(super) struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
}
