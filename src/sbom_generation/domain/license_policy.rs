/// How to handle packages with unknown (None) licenses.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum UnknownLicenseHandling {
    /// Emit a warning but do not fail (default).
    #[default]
    Warn,
    /// Treat as a violation.
    Deny,
    /// Silently allow.
    Allow,
}

/// A case-insensitive glob pattern for matching license identifiers.
#[derive(Debug, Clone)]
pub struct LicensePattern {
    original: String,
    matcher: LicensePatternMatcher,
}

#[derive(Debug, Clone)]
enum LicensePatternMatcher {
    /// Exact match (no wildcards).
    Exact(String),
    /// Prefix match: `MIT*` → starts with "mit".
    Prefix(String),
    /// Suffix match: `*GPL` → ends with "gpl".
    Suffix(String),
    /// Contains match: `*GPL*` → contains "gpl".
    Contains(String),
    /// Multiple wildcards: split into segments between `*`.
    Multiple(Vec<String>),
}

impl LicensePattern {
    pub fn new(pattern: &str) -> Option<Self> {
        let trimmed = pattern.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return None;
        }

        let lower = trimmed.to_lowercase();

        let matcher = if !lower.contains('*') {
            LicensePatternMatcher::Exact(lower)
        } else if let Some(rest) = lower.strip_prefix('*') {
            if let Some(inner) = rest.strip_suffix('*') {
                // *inner* pattern
                if inner.contains('*') {
                    Self::build_multiple(&lower)
                } else {
                    LicensePatternMatcher::Contains(inner.to_string())
                }
            } else if rest.contains('*') {
                Self::build_multiple(&lower)
            } else {
                LicensePatternMatcher::Suffix(rest.to_string())
            }
        } else if let Some(prefix) = lower.strip_suffix('*') {
            if prefix.contains('*') {
                Self::build_multiple(&lower)
            } else {
                LicensePatternMatcher::Prefix(prefix.to_string())
            }
        } else {
            Self::build_multiple(&lower)
        };

        Some(Self {
            original: trimmed.to_string(),
            matcher,
        })
    }

    fn build_multiple(lower: &str) -> LicensePatternMatcher {
        let segments: Vec<String> = lower
            .split('*')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        LicensePatternMatcher::Multiple(segments)
    }

    /// Returns the original pattern string.
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Tests whether `license` matches this pattern (case-insensitive).
    pub fn matches(&self, license: &str) -> bool {
        let lower = license.to_lowercase();
        match &self.matcher {
            LicensePatternMatcher::Exact(val) => lower == *val,
            LicensePatternMatcher::Prefix(prefix) => lower.starts_with(prefix.as_str()),
            LicensePatternMatcher::Suffix(suffix) => lower.ends_with(suffix.as_str()),
            LicensePatternMatcher::Contains(inner) => lower.contains(inner.as_str()),
            LicensePatternMatcher::Multiple(segments) => {
                let mut pos = 0;
                for seg in segments {
                    match lower[pos..].find(seg.as_str()) {
                        Some(idx) => pos += idx + seg.len(),
                        None => return false,
                    }
                }
                true
            }
        }
    }
}

/// A license compliance policy with allow/deny lists and unknown handling.
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    pub allow: Vec<LicensePattern>,
    pub deny: Vec<LicensePattern>,
    pub unknown: UnknownLicenseHandling,
}

impl LicensePolicy {
    /// Constructs a policy by compiling string patterns.
    ///
    /// Invalid patterns (empty / wildcard-only) are silently skipped.
    pub fn new(allow: &[String], deny: &[String], unknown: UnknownLicenseHandling) -> Self {
        Self {
            allow: allow
                .iter()
                .filter_map(|p| LicensePattern::new(p))
                .collect(),
            deny: deny.iter().filter_map(|p| LicensePattern::new(p)).collect(),
            unknown,
        }
    }
}

/// Reason a package violated the policy.
#[derive(Debug, Clone, PartialEq)]
pub enum ViolationReason {
    /// License matched a deny pattern.
    Denied,
    /// License did not match any allow pattern.
    NotAllowed,
    /// License is unknown and the policy denies unknowns.
    UnknownLicense,
}

impl ViolationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Denied => "Denied by policy",
            Self::NotAllowed => "Not in allow list",
            Self::UnknownLicense => "Unknown license",
        }
    }
}

/// A single package that violates the license policy.
#[derive(Debug, Clone)]
pub struct LicenseViolation {
    pub package_name: String,
    pub package_version: String,
    pub license: Option<String>,
    pub reason: ViolationReason,
    pub matched_pattern: Option<String>,
}

/// A package whose license is unknown, handled as a warning.
#[derive(Debug, Clone)]
pub struct LicenseWarning {
    pub package_name: String,
    pub package_version: String,
}

/// Result of a license compliance check.
#[derive(Debug, Clone)]
pub struct LicenseComplianceResult {
    pub violations: Vec<LicenseViolation>,
    pub warnings: Vec<LicenseWarning>,
}

impl LicenseComplianceResult {
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- LicensePattern tests --

    #[test]
    fn test_empty_pattern_rejected() {
        assert!(LicensePattern::new("").is_none());
        assert!(LicensePattern::new("  ").is_none());
    }

    #[test]
    fn test_wildcard_only_rejected() {
        assert!(LicensePattern::new("*").is_none());
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        let p = LicensePattern::new("MIT").unwrap();
        assert!(p.matches("MIT"));
        assert!(p.matches("mit"));
        assert!(p.matches("Mit"));
        assert!(!p.matches("MIT-0"));
    }

    #[test]
    fn test_prefix_match() {
        let p = LicensePattern::new("BSD-*").unwrap();
        assert!(p.matches("BSD-2-Clause"));
        assert!(p.matches("BSD-3-Clause"));
        assert!(p.matches("bsd-3-clause"));
        assert!(!p.matches("MIT"));
    }

    #[test]
    fn test_suffix_match() {
        let p = LicensePattern::new("*-only").unwrap();
        assert!(p.matches("GPL-3.0-only"));
        assert!(p.matches("gpl-3.0-only"));
        assert!(!p.matches("GPL-3.0-or-later"));
    }

    #[test]
    fn test_contains_match() {
        let p = LicensePattern::new("*GPL*").unwrap();
        assert!(p.matches("GPL-3.0"));
        assert!(p.matches("LGPL-2.1"));
        assert!(p.matches("AGPL-3.0-only"));
        assert!(!p.matches("MIT"));
    }

    #[test]
    fn test_multiple_wildcards() {
        let p = LicensePattern::new("*GPL*only").unwrap();
        assert!(p.matches("GPL-3.0-only"));
        assert!(p.matches("AGPL-3.0-only"));
        assert!(!p.matches("GPL-3.0-or-later"));
    }

    // -- LicensePolicy tests --

    #[test]
    fn test_policy_skips_invalid_patterns() {
        let policy = LicensePolicy::new(
            &["MIT".to_string(), "".to_string(), "*".to_string()],
            &[],
            UnknownLicenseHandling::Warn,
        );
        assert_eq!(policy.allow.len(), 1);
    }

    // -- ViolationReason display --

    #[test]
    fn test_violation_reason_as_str() {
        assert_eq!(ViolationReason::Denied.as_str(), "Denied by policy");
        assert_eq!(ViolationReason::NotAllowed.as_str(), "Not in allow list");
        assert_eq!(ViolationReason::UnknownLicense.as_str(), "Unknown license");
    }
}
