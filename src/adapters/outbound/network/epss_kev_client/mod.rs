mod dto;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;

use crate::i18n::{Locale, Messages};
use crate::ports::outbound::ExploitabilityRepository;
use crate::sbom_generation::domain::exploitability::ExploitabilityInfo;
use crate::shared::response_size_guard;
use crate::shared::Result;
use dto::{EpssApiResponse, KevCatalogResponse};

/// Network adapter fetching EPSS scores from FIRST.org and CISA KEV catalog status.
///
/// Combines two independent data sources into a single `ExploitabilityInfo` per CVE:
/// - **EPSS**: batched GET against `https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...`
/// - **KEV**: single GET of the CISA KEV JSON feed, parsed into a `HashSet<String>`
///
/// Non-CVE identifiers (e.g. GHSA, PYSEC) are filtered out before any HTTP call.
/// A failed fetch soft-fails: affected CVEs get no exploitability data rather than
/// aborting the run.
#[derive(Clone)]
pub struct EpssKevClient {
    client: Client,
    epss_base_url: String,
    kev_url: String,
    locale: Locale,
}

impl EpssKevClient {
    const EPSS_API_BASE: &'static str = "https://api.first.org/data/v1/epss";
    const KEV_CATALOG_URL: &'static str =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    const TIMEOUT_SECONDS: u64 = 30;
    const RATE_LIMIT_MS: u64 = 100;
    const MAX_BATCH_SIZE: usize = 100;
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

    /// Creates a new client using the default EPSS and KEV endpoint URLs.
    pub fn new(locale: Locale) -> Result<Self> {
        Self::build(
            Self::EPSS_API_BASE.to_string(),
            Self::KEV_CATALOG_URL.to_string(),
            locale,
        )
    }

    #[cfg(test)]
    fn new_with_urls(
        epss_base_url: impl Into<String>,
        kev_url: impl Into<String>,
        locale: Locale,
    ) -> Result<Self> {
        Self::build(epss_base_url.into(), kev_url.into(), locale)
    }

    fn build(epss_base_url: String, kev_url: String, locale: Locale) -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = Client::builder()
            .timeout(Duration::from_secs(Self::TIMEOUT_SECONDS))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            epss_base_url,
            kev_url,
            locale,
        })
    }

    /// Returns true if the identifier matches the CVE pattern `CVE-YYYY-NNNNN+`.
    fn is_cve_id(id: &str) -> bool {
        let Some(rest) = id.strip_prefix("CVE-") else {
            return false;
        };
        let Some((year, seq)) = rest.split_once('-') else {
            return false;
        };
        year.len() == 4
            && year.chars().all(|c| c.is_ascii_digit())
            && !seq.is_empty()
            && seq.chars().all(|c| c.is_ascii_digit())
    }

    /// Fetches EPSS data for a batch of CVE IDs (max `MAX_BATCH_SIZE`).
    async fn fetch_epss_batch(&self, cve_ids: &[&str]) -> Result<HashMap<String, (f32, f32)>> {
        let cve_param = cve_ids.join(",");
        let url = format!("{}?cve={}", self.epss_base_url, cve_param);

        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("EPSS API returned status code {}", response.status());
        }

        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some("EPSS batch query"),
        )
        .await?;
        let api_response: EpssApiResponse = serde_json::from_slice(&bytes)?;

        let mut result = HashMap::new();
        for entry in api_response.data {
            if let (Ok(score), Ok(percentile)) =
                (entry.epss.parse::<f32>(), entry.percentile.parse::<f32>())
            {
                result.insert(entry.cve, (score, percentile));
            }
        }
        Ok(result)
    }

    /// Fetches the CISA KEV catalog and returns CVE IDs as a HashSet.
    async fn fetch_kev_catalog(&self) -> Result<HashSet<String>> {
        let response = self.client.get(&self.kev_url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("KEV catalog returned status code {}", response.status());
        }

        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some("CISA KEV catalog"),
        )
        .await?;
        let catalog: KevCatalogResponse = serde_json::from_slice(&bytes)?;

        Ok(catalog
            .vulnerabilities
            .into_iter()
            .map(|v| v.cve_id)
            .collect())
    }
}

#[async_trait]
impl ExploitabilityRepository for EpssKevClient {
    async fn fetch_exploitability(
        &self,
        cve_ids: Vec<String>,
    ) -> Result<HashMap<String, ExploitabilityInfo>> {
        let cve_only: Vec<&str> = cve_ids
            .iter()
            .filter(|id| Self::is_cve_id(id))
            .map(|s| s.as_str())
            .collect();

        if cve_only.is_empty() {
            return Ok(HashMap::new());
        }

        // Fetch EPSS data in batches, soft-failing on error
        let mut epss_data: HashMap<String, (f32, f32)> = HashMap::new();
        for (i, chunk) in cve_only.chunks(Self::MAX_BATCH_SIZE).enumerate() {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(Self::RATE_LIMIT_MS)).await;
            }
            match self.fetch_epss_batch(chunk).await {
                Ok(batch) => epss_data.extend(batch),
                Err(e) => {
                    let msgs = Messages::for_locale(self.locale);
                    eprintln!(
                        "{}",
                        Messages::format(
                            msgs.warn_epss_fetch_failed,
                            &[&(i + 1).to_string(), &e.to_string()]
                        )
                    );
                }
            }
        }

        // Fetch KEV catalog, soft-failing on error
        let kev_set: HashSet<String> = match self.fetch_kev_catalog().await {
            Ok(set) => set,
            Err(e) => {
                let msgs = Messages::for_locale(self.locale);
                eprintln!(
                    "{}",
                    Messages::format(msgs.warn_kev_fetch_failed, &[&e.to_string()])
                );
                HashSet::new()
            }
        };

        // Combine EPSS + KEV into ExploitabilityInfo
        let mut result = HashMap::new();
        for cve_id in &cve_only {
            let in_kev = kev_set.contains(*cve_id);
            let epss = epss_data.get(*cve_id).copied();

            match (epss, in_kev) {
                (Some((score, percentile)), _) => {
                    if let Ok(info) = ExploitabilityInfo::new(score, percentile, in_kev) {
                        result.insert(cve_id.to_string(), info);
                    }
                }
                (None, true) => {
                    // KEV-listed but no EPSS data: use 0.0 defaults for EPSS
                    if let Ok(info) = ExploitabilityInfo::new(0.0, 0.0, true) {
                        result.insert(cve_id.to_string(), info);
                    }
                }
                (None, false) => {
                    // No data from either source
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_mock_server() -> (MockServer, String, String) {
        let mock_server = MockServer::start().await;
        let epss_url = format!("{}/data/v1/epss", mock_server.uri());
        let kev_url = format!("{}/kev.json", mock_server.uri());
        (mock_server, epss_url, kev_url)
    }

    #[test]
    fn test_is_cve_id() {
        assert!(EpssKevClient::is_cve_id("CVE-2024-1234"));
        assert!(EpssKevClient::is_cve_id("CVE-2024-12345"));
        assert!(EpssKevClient::is_cve_id("CVE-1999-0001"));
        assert!(!EpssKevClient::is_cve_id("GHSA-xxxx-yyyy-zzzz"));
        assert!(!EpssKevClient::is_cve_id("PYSEC-2024-1"));
        assert!(!EpssKevClient::is_cve_id("CVE-"));
        assert!(!EpssKevClient::is_cve_id("CVE-2024"));
        assert!(!EpssKevClient::is_cve_id("CVE-2024-"));
        assert!(!EpssKevClient::is_cve_id("CVE-20AB-1234"));
        assert!(!EpssKevClient::is_cve_id("cve-2024-1234"));
        assert!(!EpssKevClient::is_cve_id(""));
    }

    #[test]
    fn test_client_creation() {
        let client = EpssKevClient::new(Locale::En);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_exploitability_happy_path() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "status-code": 200,
                "version": "1.0",
                "total": 2,
                "offset": 0,
                "limit": 100,
                "data": [
                    { "cve": "CVE-2024-0001", "epss": "0.50000", "percentile": "0.97000" },
                    { "cve": "CVE-2024-0002", "epss": "0.10000", "percentile": "0.30000" }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "CISA KEV",
                "catalogVersion": "2024.01.01",
                "vulnerabilities": [
                    { "cveID": "CVE-2024-0001" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec![
                "CVE-2024-0001".to_string(),
                "CVE-2024-0002".to_string(),
            ])
            .await
            .unwrap();

        assert_eq!(result.len(), 2);

        let info1 = result.get("CVE-2024-0001").unwrap();
        assert!((info1.epss_percentile() - 0.97).abs() < 0.001);
        assert!(info1.in_kev());

        let info2 = result.get("CVE-2024-0002").unwrap();
        assert!((info2.epss_percentile() - 0.3).abs() < 0.001);
        assert!(!info2.in_kev());
    }

    #[tokio::test]
    async fn test_non_cve_ids_are_filtered_out() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        // No HTTP calls should be made since all IDs are non-CVE
        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec![
                "GHSA-xxxx-yyyy-zzzz".to_string(),
                "PYSEC-2024-1".to_string(),
            ])
            .await
            .unwrap();

        assert!(result.is_empty());
        // Verify no requests were made
        assert_eq!(mock_server.received_requests().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_mixed_cve_and_non_cve_ids() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "data": [
                    { "cve": "CVE-2024-0001", "epss": "0.50000", "percentile": "0.97000" }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": []
            })))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec![
                "CVE-2024-0001".to_string(),
                "GHSA-xxxx-yyyy-zzzz".to_string(),
            ])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("CVE-2024-0001"));
    }

    #[tokio::test]
    async fn test_epss_failure_soft_fails() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    { "cveID": "CVE-2024-0001" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        // KEV data still available despite EPSS failure
        assert_eq!(result.len(), 1);
        let info = result.get("CVE-2024-0001").unwrap();
        assert!(info.in_kev());
    }

    #[tokio::test]
    async fn test_kev_failure_soft_fails() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "data": [
                    { "cve": "CVE-2024-0001", "epss": "0.50000", "percentile": "0.97000" }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        // EPSS data still available despite KEV failure
        assert_eq!(result.len(), 1);
        let info = result.get("CVE-2024-0001").unwrap();
        assert!(!info.in_kev());
        assert!((info.epss_percentile() - 0.97).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_both_failures_soft_fail_to_empty() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_epss_failure_soft_fails_ja_locale() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    { "cveID": "CVE-2024-0001" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::Ja).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.get("CVE-2024-0001").unwrap().in_kev());
    }

    #[tokio::test]
    async fn test_kev_failure_soft_fails_ja_locale() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "data": [
                    { "cve": "CVE-2024-0001", "epss": "0.50000", "percentile": "0.97000" }
                ]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::Ja).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(!result.get("CVE-2024-0001").unwrap().in_kev());
        assert!((result.get("CVE-2024-0001").unwrap().epss_percentile() - 0.97).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_empty_input_returns_empty() {
        let client = EpssKevClient::new(Locale::En).unwrap();
        let result = client.fetch_exploitability(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_kev_only_cve_gets_zero_epss_defaults() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        // EPSS returns empty data for this CVE
        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "data": []
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": [
                    { "cveID": "CVE-2024-0001" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client
            .fetch_exploitability(vec!["CVE-2024-0001".to_string()])
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        let info = result.get("CVE-2024-0001").unwrap();
        assert!(info.in_kev());
        assert!((info.epss_percentile() - 0.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_batch_cap_is_respected() {
        let (mock_server, epss_url, kev_url) = setup_mock_server().await;

        Mock::given(method("GET"))
            .and(path("/data/v1/epss"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "data": []
            })))
            .expect(2) // 150 CVEs / 100 batch cap = 2 requests
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "vulnerabilities": []
            })))
            .mount(&mock_server)
            .await;

        // Create 150 CVE IDs to force 2 batches
        let cve_ids: Vec<String> = (1..=150).map(|i| format!("CVE-2024-{:04}", i)).collect();

        let client = EpssKevClient::new_with_urls(epss_url, kev_url, Locale::En).unwrap();
        let result = client.fetch_exploitability(cve_ids).await.unwrap();

        // No EPSS data returned, no KEV matches → empty
        assert!(result.is_empty());
    }
}
