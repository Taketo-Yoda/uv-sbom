use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use std::cell::RefCell;
use std::collections::HashMap;

/// Maximum number of exclude patterns to prevent DoS attacks
const MAX_EXCLUDE_PATTERNS: usize = 64;

/// Maximum length of a single exclude pattern to prevent DoS attacks
const MAX_PATTERN_LENGTH: usize = 255;

/// PackageFilter - Filters packages based on exclusion patterns
///
/// Supports wildcard patterns using '*' to match zero or more characters.
/// Patterns are case-sensitive and validated against a character whitelist.
#[derive(Debug)]
pub struct PackageFilter {
    patterns: Vec<ExcludePattern>,
}

impl PackageFilter {
    /// Creates a new PackageFilter from raw pattern strings
    ///
    /// # Arguments
    /// * `patterns` - Vector of pattern strings (e.g., "debug-*", "*-dev")
    ///
    /// # Returns
    /// Result containing the PackageFilter or an error if validation fails
    ///
    /// # Errors
    /// - Too many patterns (> MAX_EXCLUDE_PATTERNS)
    /// - Invalid pattern format (length, characters)
    pub fn new(patterns: Vec<String>) -> Result<Self> {
        // Check pattern count
        if patterns.len() > MAX_EXCLUDE_PATTERNS {
            anyhow::bail!(
                "Too many exclusion patterns: {} (maximum: {})",
                patterns.len(),
                MAX_EXCLUDE_PATTERNS
            );
        }

        // Validate and compile each pattern
        let mut compiled_patterns = Vec::new();
        for pattern in patterns {
            let exclude_pattern = ExcludePattern::new(pattern)?;
            compiled_patterns.push(exclude_pattern);
        }

        Ok(Self {
            patterns: compiled_patterns,
        })
    }

    /// Filters packages, returning only those that don't match exclusion patterns
    ///
    /// # Arguments
    /// * `packages` - Vector of Package objects to filter
    ///
    /// # Returns
    /// Filtered vector containing only packages that don't match any exclusion pattern
    pub fn filter_packages(&self, packages: Vec<Package>) -> Vec<Package> {
        packages
            .into_iter()
            .filter(|pkg| !self.matches(pkg.name()))
            .collect()
    }

    /// Filters dependency map by removing excluded packages
    ///
    /// Removes excluded packages from both map keys and dependency lists
    ///
    /// # Arguments
    /// * `dependency_map` - HashMap mapping package names to their dependencies
    ///
    /// # Returns
    /// Filtered dependency map with excluded packages removed
    pub fn filter_dependency_map(
        &self,
        mut dependency_map: HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        // Remove excluded packages from map keys
        dependency_map.retain(|package_name, _| !self.matches(package_name));

        // Remove excluded packages from dependency lists
        for deps in dependency_map.values_mut() {
            deps.retain(|dep_name| !self.matches(dep_name));
        }

        dependency_map
    }

    /// Checks if a package name matches any exclusion pattern
    fn matches(&self, package_name: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(package_name))
    }

    /// Returns a list of patterns that did not match any packages
    ///
    /// This method should be called after filtering to identify patterns
    /// that had no effect on the package list.
    ///
    /// # Returns
    /// Vector of pattern strings that did not match any packages
    pub fn get_unmatched_patterns(&self) -> Vec<String> {
        self.patterns
            .iter()
            .filter(|p| !*p.matched.borrow())
            .map(|p| p.original.clone())
            .collect()
    }
}

/// Represents a single exclusion pattern with its compiled matcher
#[derive(Debug)]
struct ExcludePattern {
    original: String,
    matcher: PatternMatcher,
    matched: RefCell<bool>,
}

impl ExcludePattern {
    /// Creates a new ExcludePattern from a pattern string
    ///
    /// # Arguments
    /// * `pattern` - Pattern string (e.g., "debug-*", "*-dev")
    ///
    /// # Returns
    /// Result containing the ExcludePattern or validation error
    fn new(pattern: String) -> Result<Self> {
        validate_pattern(&pattern)?;

        let matcher = compile_pattern(&pattern);

        Ok(Self {
            original: pattern,
            matcher,
            matched: RefCell::new(false),
        })
    }

    /// Checks if a package name matches this pattern
    fn matches(&self, package_name: &str) -> bool {
        let is_match = self.matcher.matches(package_name);
        if is_match {
            *self.matched.borrow_mut() = true;
        }
        is_match
    }
}

/// Pattern matcher types for efficient matching
#[derive(Debug)]
enum PatternMatcher {
    /// Exact match: "package-name"
    Exact(String),
    /// Prefix wildcard: "*-suffix"
    Prefix(String),
    /// Suffix wildcard: "prefix-*"
    Suffix(String),
    /// Contains wildcard: "*middle*"
    Contains(String),
    /// Multiple wildcards: "pre*fix*suf"
    Multiple(Vec<String>),
}

impl PatternMatcher {
    /// Checks if a package name matches this pattern
    fn matches(&self, package_name: &str) -> bool {
        match self {
            PatternMatcher::Exact(s) => package_name == s,
            PatternMatcher::Prefix(suffix) => package_name.ends_with(suffix),
            PatternMatcher::Suffix(prefix) => package_name.starts_with(prefix),
            PatternMatcher::Contains(middle) => package_name.contains(middle),
            PatternMatcher::Multiple(parts) => {
                // Match multiple wildcards by checking if all parts appear in order
                let mut current_pos = 0;
                for part in parts {
                    if let Some(pos) = package_name[current_pos..].find(part) {
                        current_pos += pos + part.len();
                    } else {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Validates a pattern string
///
/// # Arguments
/// * `pattern` - Pattern string to validate
///
/// # Returns
/// Ok(()) if valid, Err with description if invalid
fn validate_pattern(pattern: &str) -> Result<()> {
    // Check if pattern is empty
    if pattern.is_empty() {
        anyhow::bail!("Exclusion pattern cannot be empty");
    }

    // Check pattern length
    if pattern.len() > MAX_PATTERN_LENGTH {
        anyhow::bail!(
            "Exclusion pattern is too long: '{}' ({} chars). Maximum: {} chars",
            pattern,
            pattern.len(),
            MAX_PATTERN_LENGTH
        );
    }

    // Validate characters
    for ch in pattern.chars() {
        if !is_valid_pattern_char(ch) {
            anyhow::bail!(
                "Exclusion pattern contains invalid character '{}' in pattern '{}'. \
                 Only alphanumeric, hyphens, underscores, dots, brackets, and asterisks (*) are allowed.",
                ch,
                pattern
            );
        }
    }

    // Reject patterns with only wildcards
    if pattern.chars().all(|c| c == '*') {
        anyhow::bail!(
            "Exclusion pattern cannot contain only wildcards: '{}'",
            pattern
        );
    }

    Ok(())
}

/// Checks if a character is valid in an exclusion pattern
fn is_valid_pattern_char(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '[' || c == ']' || c == '*'
}

/// Compiles a pattern string into an optimized matcher
///
/// # Arguments
/// * `pattern` - Pattern string to compile
///
/// # Returns
/// Optimized PatternMatcher for the given pattern
fn compile_pattern(pattern: &str) -> PatternMatcher {
    let wildcard_count = pattern.matches('*').count();

    match wildcard_count {
        0 => {
            // No wildcards: exact match
            PatternMatcher::Exact(pattern.to_string())
        }
        1 => {
            // Single wildcard: optimize for common cases
            if let Some(stripped) = pattern.strip_prefix('*') {
                // "*-suffix" -> ends_with check
                PatternMatcher::Prefix(stripped.to_string())
            } else if let Some(stripped) = pattern.strip_suffix('*') {
                // "prefix-*" -> starts_with check
                PatternMatcher::Suffix(stripped.to_string())
            } else {
                // "*middle*" case won't happen with single wildcard
                // This is actually "prefix*suffix" -> split and use Multiple
                let parts: Vec<String> = pattern.split('*').map(|s| s.to_string()).collect();
                PatternMatcher::Multiple(parts)
            }
        }
        2 => {
            // Two wildcards
            if pattern.starts_with('*') && pattern.ends_with('*') {
                // "*middle*" -> contains check
                let middle = &pattern[1..pattern.len() - 1];
                PatternMatcher::Contains(middle.to_string())
            } else {
                // Other patterns with 2 wildcards -> use Multiple
                let parts: Vec<String> = pattern
                    .split('*')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                PatternMatcher::Multiple(parts)
            }
        }
        _ => {
            // Multiple wildcards: general case
            let parts: Vec<String> = pattern
                .split('*')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            PatternMatcher::Multiple(parts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let filter = PackageFilter::new(vec!["requests".to_string()]).unwrap();
        assert!(filter.matches("requests"));
        assert!(!filter.matches("requests-extra"));
        assert!(!filter.matches("my-requests"));
    }

    #[test]
    fn test_prefix_wildcard() {
        let filter = PackageFilter::new(vec!["*-dev".to_string()]).unwrap();
        assert!(filter.matches("pytest-dev"));
        assert!(filter.matches("mylib-dev"));
        assert!(!filter.matches("dev"));
        assert!(!filter.matches("dev-tools"));
        assert!(!filter.matches("pytest-dev-extra"));
    }

    #[test]
    fn test_suffix_wildcard() {
        let filter = PackageFilter::new(vec!["debug-*".to_string()]).unwrap();
        assert!(filter.matches("debug-tool"));
        assert!(filter.matches("debug-utils"));
        assert!(!filter.matches("my-debug"));
        assert!(!filter.matches("debugger"));
    }

    #[test]
    fn test_contains_wildcard() {
        let filter = PackageFilter::new(vec!["*-test-*".to_string()]).unwrap();
        assert!(filter.matches("pytest-test-utils"));
        assert!(filter.matches("my-test-lib"));
        assert!(filter.matches("a-test-b"));
        assert!(!filter.matches("testing"));
        assert!(!filter.matches("test"));
    }

    #[test]
    fn test_multiple_wildcards() {
        let filter = PackageFilter::new(vec!["py*-test*".to_string()]).unwrap();
        assert!(filter.matches("pytest-testing"));
        assert!(filter.matches("python-tests"));
        assert!(filter.matches("py-test"));
        assert!(!filter.matches("mypy-lint"));
        assert!(!filter.matches("test-python"));
    }

    #[test]
    fn test_pattern_validation_too_long() {
        let long_pattern = "a".repeat(300);
        let result = PackageFilter::new(vec![long_pattern]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_pattern_validation_invalid_chars() {
        let result = PackageFilter::new(vec!["package@name".to_string()]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid character"));
    }

    #[test]
    fn test_pattern_validation_empty() {
        let result = PackageFilter::new(vec!["".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_pattern_validation_only_wildcards() {
        let result = PackageFilter::new(vec!["***".to_string()]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot contain only wildcards"));
    }

    #[test]
    fn test_pattern_validation_too_many_patterns() {
        let patterns: Vec<String> = (0..65).map(|i| format!("pattern{}", i)).collect();
        let result = PackageFilter::new(patterns);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many"));
    }

    #[test]
    fn test_pattern_count_boundary_63_patterns() {
        let patterns: Vec<String> = (0..63).map(|i| format!("pattern{}", i)).collect();
        let result = PackageFilter::new(patterns);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_count_boundary_64_patterns() {
        let patterns: Vec<String> = (0..64).map(|i| format!("pattern{}", i)).collect();
        let result = PackageFilter::new(patterns);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_count_boundary_65_patterns() {
        let patterns: Vec<String> = (0..65).map(|i| format!("pattern{}", i)).collect();
        let result = PackageFilter::new(patterns);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many"));
    }

    #[test]
    fn test_pattern_length_boundary_254_chars() {
        let pattern = "a".repeat(254);
        let result = PackageFilter::new(vec![pattern]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_length_boundary_255_chars() {
        let pattern = "a".repeat(255);
        let result = PackageFilter::new(vec![pattern]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_length_boundary_256_chars() {
        let pattern = "a".repeat(256);
        let result = PackageFilter::new(vec![pattern]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_filter_packages() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pytest".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec!["pytest".to_string()]).unwrap();
        let filtered = filter.filter_packages(packages);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name(), "requests");
        assert_eq!(filtered[1].name(), "numpy");
    }

    #[test]
    fn test_filter_packages_with_wildcard() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pytest-dev".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("mypy-dev".to_string(), "3.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "4.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec!["*-dev".to_string()]).unwrap();
        let filtered = filter.filter_packages(packages);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name(), "requests");
        assert_eq!(filtered[1].name(), "numpy");
    }

    #[test]
    fn test_filter_packages_multiple_patterns() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pytest".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec!["pytest".to_string(), "numpy".to_string()]).unwrap();
        let filtered = filter.filter_packages(packages);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name(), "requests");
    }

    #[test]
    fn test_empty_pattern_list() {
        let filter = PackageFilter::new(vec![]).unwrap();
        assert!(!filter.matches("anything"));
    }

    #[test]
    fn test_filter_dependency_map() {
        let mut dependency_map = HashMap::new();
        dependency_map.insert(
            "app".to_string(),
            vec!["requests".to_string(), "pytest".to_string()],
        );
        dependency_map.insert("pytest".to_string(), vec!["pluggy".to_string()]);
        dependency_map.insert("requests".to_string(), vec!["urllib3".to_string()]);

        let filter = PackageFilter::new(vec!["pytest".to_string()]).unwrap();
        let filtered = filter.filter_dependency_map(dependency_map);

        // pytest should be removed from keys
        assert!(!filtered.contains_key("pytest"));
        // pytest should be removed from app's dependencies
        assert_eq!(filtered.get("app").unwrap(), &vec!["requests".to_string()]);
        // Other entries should remain
        assert!(filtered.contains_key("requests"));
    }

    #[test]
    fn test_case_sensitive_matching() {
        let filter = PackageFilter::new(vec!["PyTest".to_string()]).unwrap();
        assert!(filter.matches("PyTest"));
        assert!(!filter.matches("pytest"));
        assert!(!filter.matches("PYTEST"));
    }

    #[test]
    fn test_pattern_with_brackets() {
        let filter = PackageFilter::new(vec!["package[extra]".to_string()]).unwrap();
        assert!(filter.matches("package[extra]"));
        assert!(!filter.matches("package"));
    }

    #[test]
    fn test_pattern_with_dots() {
        let filter = PackageFilter::new(vec!["com.example.*".to_string()]).unwrap();
        assert!(filter.matches("com.example.package"));
        assert!(filter.matches("com.example.test"));
        assert!(!filter.matches("com.other.package"));
    }

    #[test]
    fn test_unmatched_patterns_all_matched() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pytest".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec!["pytest".to_string()]).unwrap();
        let _filtered = filter.filter_packages(packages);

        // pytest pattern should have matched
        let unmatched = filter.get_unmatched_patterns();
        assert_eq!(unmatched.len(), 0);
    }

    #[test]
    fn test_unmatched_patterns_none_matched() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let filter =
            PackageFilter::new(vec!["pytest".to_string(), "non-existent".to_string()]).unwrap();
        let _filtered = filter.filter_packages(packages);

        // Both patterns should be unmatched
        let unmatched = filter.get_unmatched_patterns();
        assert_eq!(unmatched.len(), 2);
        assert!(unmatched.contains(&"pytest".to_string()));
        assert!(unmatched.contains(&"non-existent".to_string()));
    }

    #[test]
    fn test_unmatched_patterns_partial_match() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("pytest".to_string(), "2.0.0".to_string()).unwrap(),
            Package::new("numpy".to_string(), "3.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec![
            "pytest".to_string(),
            "non-existent".to_string(),
            "req*".to_string(),
        ])
        .unwrap();
        let _filtered = filter.filter_packages(packages);

        // Only "non-existent" should be unmatched
        let unmatched = filter.get_unmatched_patterns();
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0], "non-existent");
    }

    #[test]
    fn test_unmatched_patterns_wildcard() {
        let packages = vec![
            Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
            Package::new("flask".to_string(), "2.0.0".to_string()).unwrap(),
        ];
        let filter = PackageFilter::new(vec!["req*".to_string(), "*-dev".to_string()]).unwrap();
        let _filtered = filter.filter_packages(packages);

        // "*-dev" should be unmatched, "req*" should match "requests"
        let unmatched = filter.get_unmatched_patterns();
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0], "*-dev");
    }
}
