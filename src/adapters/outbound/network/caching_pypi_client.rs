use crate::ports::outbound::{LicenseRepository, PyPiMetadata};
use crate::shared::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;

/// Cache key for license information
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    package_name: String,
    version: String,
}

impl CacheKey {
    fn new(package_name: &str, version: &str) -> Self {
        Self {
            package_name: package_name.to_string(),
            version: version.to_string(),
        }
    }
}

/// CachingPyPiLicenseRepository wraps a LicenseRepository and adds in-memory caching.
///
/// This adapter implements the decorator pattern to add caching capability
/// to any LicenseRepository implementation. The cache is thread-safe and
/// suitable for concurrent access.
///
/// # Architecture
/// In hexagonal architecture, caching is an implementation detail of the adapter layer.
/// The domain layer only cares about fetching license information - whether it comes
/// from cache or API is transparent to the domain.
pub struct CachingPyPiLicenseRepository<R: LicenseRepository> {
    inner: R,
    cache: Arc<DashMap<CacheKey, PyPiMetadata>>,
}

impl<R: LicenseRepository> CachingPyPiLicenseRepository<R> {
    /// Creates a new caching repository wrapping the given inner repository
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Returns the current cache size (for testing/monitoring)
    #[cfg(test)]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

#[async_trait]
impl<R: LicenseRepository> LicenseRepository for CachingPyPiLicenseRepository<R> {
    async fn fetch_license_info(&self, package_name: &str, version: &str) -> Result<PyPiMetadata> {
        let key = CacheKey::new(package_name, version);

        // Check cache first
        if let Some(cached) = self.cache.get(&key) {
            return Ok(cached.clone());
        }

        // Cache miss: fetch from inner repository
        let metadata = self.inner.fetch_license_info(package_name, version).await?;

        // Store in cache
        self.cache.insert(key, metadata.clone());

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock repository for testing that tracks call counts
    struct MockLicenseRepository {
        call_count: AtomicUsize,
    }

    impl MockLicenseRepository {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }

        fn get_call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LicenseRepository for MockLicenseRepository {
        async fn fetch_license_info(
            &self,
            package_name: &str,
            _version: &str,
        ) -> Result<PyPiMetadata> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok((
                Some(format!("{}-license", package_name)),
                Some("MIT".to_string()),
                vec!["License :: OSI Approved :: MIT License".to_string()],
                Some(format!("{} description", package_name)),
            ))
        }
    }

    #[tokio::test]
    async fn test_caching_repository_returns_cached_value() {
        let mock = MockLicenseRepository::new();
        let caching_repo = CachingPyPiLicenseRepository::new(mock);

        // First call - should hit the inner repository
        let result1 = caching_repo
            .fetch_license_info("requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(result1.0, Some("requests-license".to_string()));
        assert_eq!(caching_repo.inner.get_call_count(), 1);

        // Second call - should return cached value
        let result2 = caching_repo
            .fetch_license_info("requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(result2.0, Some("requests-license".to_string()));
        // Call count should still be 1 (cached)
        assert_eq!(caching_repo.inner.get_call_count(), 1);

        // Cache size should be 1
        assert_eq!(caching_repo.cache_size(), 1);
    }

    #[tokio::test]
    async fn test_caching_repository_different_versions_cached_separately() {
        let mock = MockLicenseRepository::new();
        let caching_repo = CachingPyPiLicenseRepository::new(mock);

        // Fetch version 2.31.0
        caching_repo
            .fetch_license_info("requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(caching_repo.inner.get_call_count(), 1);

        // Fetch version 2.32.0 - should hit inner repository
        caching_repo
            .fetch_license_info("requests", "2.32.0")
            .await
            .unwrap();
        assert_eq!(caching_repo.inner.get_call_count(), 2);

        // Cache size should be 2
        assert_eq!(caching_repo.cache_size(), 2);
    }

    #[tokio::test]
    async fn test_caching_repository_different_packages_cached_separately() {
        let mock = MockLicenseRepository::new();
        let caching_repo = CachingPyPiLicenseRepository::new(mock);

        // Fetch requests
        let result1 = caching_repo
            .fetch_license_info("requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(result1.0, Some("requests-license".to_string()));

        // Fetch flask - should hit inner repository
        let result2 = caching_repo
            .fetch_license_info("flask", "2.3.0")
            .await
            .unwrap();
        assert_eq!(result2.0, Some("flask-license".to_string()));

        assert_eq!(caching_repo.inner.get_call_count(), 2);
        assert_eq!(caching_repo.cache_size(), 2);
    }

    #[tokio::test]
    async fn test_cache_key_equality() {
        let key1 = CacheKey::new("requests", "2.31.0");
        let key2 = CacheKey::new("requests", "2.31.0");
        let key3 = CacheKey::new("requests", "2.32.0");
        let key4 = CacheKey::new("flask", "2.31.0");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }
}
