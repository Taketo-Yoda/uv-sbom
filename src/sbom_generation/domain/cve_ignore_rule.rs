//! Domain value object for one entry of the CVE ignore list.

/// A rule that excludes one vulnerability ID from vulnerability results.
///
/// This is the domain's own, serde-free counterpart of the config file's
/// `IgnoreCve` entry; the application layer converts between them, so the
/// domain never depends on the config layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveIgnoreRule {
    /// The vulnerability identifier to ignore (e.g. "CVE-2024-1234"), matched exactly.
    pub id: String,
    /// Why the vulnerability is ignored, if a reason was given.
    pub reason: Option<String>,
}

impl CveIgnoreRule {
    /// Returns the reason for ignoring this vulnerability, if provided.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reason_with_and_without_value() {
        let with = CveIgnoreRule {
            id: "CVE-2024-1".to_string(),
            reason: Some("not reachable".to_string()),
        };
        let without = CveIgnoreRule {
            id: "CVE-2024-2".to_string(),
            reason: None,
        };
        assert_eq!(with.reason(), Some("not reachable"));
        assert_eq!(without.reason(), None);
    }
}
