use crate::sbom_generation::domain::license_policy::{LicensePolicy, UnknownLicenseHandling};
use uv_sbom::config;

/// Resolve the `unknown` license handling from its config string representation.
/// Unrecognized or unspecified values default to `Warn`. Config-file values are
/// already validated at load time (`config.rs`), so the fallback here is defensive.
fn resolve_unknown_license_handling(config: Option<&str>) -> UnknownLicenseHandling {
    config
        .map(|s| match s.to_lowercase().as_str() {
            "deny" => UnknownLicenseHandling::Deny,
            "allow" => UnknownLicenseHandling::Allow,
            _ => UnknownLicenseHandling::Warn,
        })
        .unwrap_or_default()
}

/// Resolve `license_policy`. `check_license` must be the already-resolved merged
/// value (not re-derived here), since config-only activation
/// (`config.check_license = true`) must also pick up the CLI-supplied lists.
///
/// If `check_license` is enabled and CLI allow/deny lists are non-empty, they
/// override the config policy entirely. Otherwise, the config policy is used if
/// present, falling back to an empty policy (default `Warn` unknown-handling).
pub(super) fn resolve_license_policy(
    check_license: bool,
    cli_allow: &[String],
    cli_deny: &[String],
    config: Option<&config::LicensePolicyConfig>,
) -> Option<LicensePolicy> {
    if !check_license {
        return None;
    }
    if !cli_allow.is_empty() || !cli_deny.is_empty() {
        // CLI provides policy — override config entirely
        return Some(LicensePolicy::new(
            cli_allow,
            cli_deny,
            UnknownLicenseHandling::default(),
        ));
    }
    if let Some(lp_config) = config {
        // Use config policy
        let unknown = resolve_unknown_license_handling(lp_config.unknown.as_deref());
        let allow = lp_config.allow.clone().unwrap_or_default();
        let deny = lp_config.deny.clone().unwrap_or_default();
        return Some(LicensePolicy::new(&allow, &deny, unknown));
    }
    // check_license enabled but no policy specified
    Some(LicensePolicy::new(
        &[],
        &[],
        UnknownLicenseHandling::default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_unknown_license_handling ---

    #[test]
    fn test_resolve_unknown_license_handling_none_defaults_to_warn() {
        assert_eq!(
            resolve_unknown_license_handling(None),
            UnknownLicenseHandling::Warn
        );
    }

    #[test]
    fn test_resolve_unknown_license_handling_deny() {
        assert_eq!(
            resolve_unknown_license_handling(Some("deny")),
            UnknownLicenseHandling::Deny
        );
    }

    #[test]
    fn test_resolve_unknown_license_handling_allow() {
        assert_eq!(
            resolve_unknown_license_handling(Some("allow")),
            UnknownLicenseHandling::Allow
        );
    }

    #[test]
    fn test_resolve_unknown_license_handling_warn_explicit() {
        assert_eq!(
            resolve_unknown_license_handling(Some("warn")),
            UnknownLicenseHandling::Warn
        );
    }

    #[test]
    fn test_resolve_unknown_license_handling_case_insensitive() {
        assert_eq!(
            resolve_unknown_license_handling(Some("DENY")),
            UnknownLicenseHandling::Deny
        );
        assert_eq!(
            resolve_unknown_license_handling(Some("Allow")),
            UnknownLicenseHandling::Allow
        );
    }

    #[test]
    fn test_resolve_unknown_license_handling_unrecognized_falls_back_to_warn() {
        // Characterization: config.rs validates this field at load time (only
        // "warn"/"deny"/"allow" pass), so this branch is defensive/unreachable
        // from a real config file. Kept as documentation of that fallback.
        assert_eq!(
            resolve_unknown_license_handling(Some("bogus")),
            UnknownLicenseHandling::Warn
        );
    }

    // --- resolve_license_policy ---

    #[test]
    fn test_resolve_license_policy_check_license_false_returns_none() {
        // The check_license guard short-circuits before any list/config is consulted.
        let cli_allow = vec!["MIT".to_string()];
        let cli_deny = vec!["GPL-3.0".to_string()];
        let config = config::LicensePolicyConfig {
            allow: Some(vec!["Apache-2.0".to_string()]),
            deny: None,
            unknown: Some("deny".to_string()),
        };
        let result = resolve_license_policy(false, &cli_allow, &cli_deny, Some(&config));
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_license_policy_cli_allow_only_overrides() {
        let cli_allow = vec!["MIT".to_string()];
        let result = resolve_license_policy(true, &cli_allow, &[], None);
        let policy = result.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "MIT");
        assert!(policy.deny.is_empty());
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_resolve_license_policy_cli_deny_only_overrides() {
        let cli_deny = vec!["GPL-3.0".to_string()];
        let result = resolve_license_policy(true, &[], &cli_deny, None);
        let policy = result.expect("policy should be Some");
        assert!(policy.allow.is_empty());
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.deny[0].as_str(), "GPL-3.0");
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_resolve_license_policy_cli_lists_override_config_entirely() {
        // CLI lists take precedence even when a config policy is also present,
        // and the CLI-only construction always uses default (Warn) unknown handling.
        let cli_allow = vec!["Apache-2.0".to_string()];
        let cli_deny = vec!["GPL-3.0".to_string()];
        let config = config::LicensePolicyConfig {
            allow: Some(vec!["MIT".to_string()]),
            deny: Some(vec!["AGPL-3.0".to_string()]),
            unknown: Some("deny".to_string()),
        };
        let result = resolve_license_policy(true, &cli_allow, &cli_deny, Some(&config));
        let policy = result.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "Apache-2.0");
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.deny[0].as_str(), "GPL-3.0");
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_resolve_license_policy_uses_config_when_cli_lists_empty() {
        let config = config::LicensePolicyConfig {
            allow: Some(vec!["MIT".to_string()]),
            deny: Some(vec!["GPL-3.0".to_string()]),
            unknown: Some("deny".to_string()),
        };
        let result = resolve_license_policy(true, &[], &[], Some(&config));
        let policy = result.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "MIT");
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.deny[0].as_str(), "GPL-3.0");
        assert_eq!(policy.unknown, UnknownLicenseHandling::Deny);
    }

    #[test]
    fn test_resolve_license_policy_config_with_none_fields_defaults_to_empty() {
        let config = config::LicensePolicyConfig {
            allow: None,
            deny: None,
            unknown: None,
        };
        let result = resolve_license_policy(true, &[], &[], Some(&config));
        let policy = result.expect("policy should be Some");
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_resolve_license_policy_no_config_no_cli_lists_yields_empty_policy() {
        let result = resolve_license_policy(true, &[], &[], None);
        let policy = result.expect("policy should be Some");
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }
}
