use crate::lockfile::Package;
use anyhow::Result;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct PyPiPackageInfo {
    info: PyPiInfo,
}

#[derive(Debug, Deserialize)]
struct PyPiInfo {
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    classifiers: Vec<String>,
}

pub fn fetch_licenses(packages: Vec<Package>) -> Result<Vec<Package>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("uv-sbom/0.1.0")
        .build()?;

    let mut enriched_packages = Vec::new();
    let total = packages.len();
    let mut successful = 0;
    let mut failed = 0;

    for (idx, mut package) in packages.into_iter().enumerate() {
        eprint!(
            "\r   Progress: {}/{} ({:.1}%) - {}",
            idx + 1,
            total,
            ((idx + 1) as f64 / total as f64) * 100.0,
            package.name
        );

        // Fetch information from PyPI API (with retry)
        match fetch_from_pypi_with_retry(&client, &package.name, &package.version) {
            Ok((license, summary)) => {
                package.license = license;
                package.description = summary;
                successful += 1;
            }
            Err(e) => {
                eprintln!(
                    "\n   ⚠️  Warning: Failed to fetch license information for {}: {}",
                    package.name, e
                );
                failed += 1;
                // Include package even if failed (without license information)
            }
        }

        enriched_packages.push(package);
    }

    eprintln!();
    eprintln!(
        "✅ License information retrieval complete: {} succeeded out of {}, {} failed",
        successful, total, failed
    );

    Ok(enriched_packages)
}

fn fetch_from_pypi_with_retry(
    client: &reqwest::blocking::Client,
    name: &str,
    version: &str,
) -> Result<(Option<String>, Option<String>)> {
    const MAX_RETRIES: u32 = 3;
    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match fetch_from_pypi(client, name, version) {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < MAX_RETRIES {
                    // Retry after a short wait
                    std::thread::sleep(Duration::from_millis(100 * attempt as u64));
                }
            }
        }
    }

    Err(last_error.unwrap())
}

fn fetch_from_pypi(
    client: &reqwest::blocking::Client,
    name: &str,
    version: &str,
) -> Result<(Option<String>, Option<String>)> {
    let url = format!("https://pypi.org/pypi/{}/{}/json", name, version);

    let response = client.get(&url).send()?;

    if !response.status().is_success() {
        anyhow::bail!(
            "PyPI API returned status code {}",
            response.status()
        );
    }

    let package_info: PyPiPackageInfo = response.json()?;

    // Retrieve license information (from license field or classifiers)
    let license = package_info
        .info
        .license
        .filter(|l| !l.is_empty() && l != "UNKNOWN")
        .or_else(|| extract_license_from_classifiers(&package_info.info.classifiers));

    Ok((license, package_info.info.summary))
}

fn extract_license_from_classifiers(classifiers: &[String]) -> Option<String> {
    for classifier in classifiers {
        if let Some(license) = classifier.strip_prefix("License :: OSI Approved :: ") {
            return Some(license.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_license_from_classifiers() {
        let classifiers = vec![
            "Programming Language :: Python :: 3".to_string(),
            "License :: OSI Approved :: MIT License".to_string(),
        ];

        let license = extract_license_from_classifiers(&classifiers);
        assert_eq!(license, Some("MIT License".to_string()));
    }

    #[test]
    fn test_extract_license_from_classifiers_not_found() {
        let classifiers = vec!["Programming Language :: Python :: 3".to_string()];

        let license = extract_license_from_classifiers(&classifiers);
        assert_eq!(license, None);
    }
}
