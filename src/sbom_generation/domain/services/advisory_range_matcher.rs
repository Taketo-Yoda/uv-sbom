//! Range matching and verdict derivation for `--incident` mode.

use crate::sbom_generation::domain::advisory::{
    Advisory, AffectedRange, IncidentVerdict, ReleaseStatus,
};
use pep440_rs::Version;
use std::str::FromStr;

/// Result of a successful advisory match. A `None` match means "not affected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryMatch {
    /// The smallest `fixed` version greater than the locked version, among the
    /// ranges that matched, as written in the advisory. `None` when no matched
    /// range carries a fix (including a match via the explicit `versions` list
    /// only). Surrounding whitespace is trimmed.
    pub fixed_version: Option<String>,
}

/// Stateless domain service evaluating an OSV advisory against a locked
/// package version, and deriving incident-mode verdicts.
///
/// Only `ECOSYSTEM` range semantics are implemented; the adapter drops other
/// range types before building the domain `Advisory`.
pub struct AdvisoryRangeMatcher;

impl AdvisoryRangeMatcher {
    /// Returns `true` when `advisory` lists `package_name` in any `affected`
    /// entry, comparing names after PEP 503 normalization (so `Flask_Login`
    /// names `flask-login`). Says nothing about whether a version is affected.
    pub fn names_package(advisory: &Advisory, package_name: &str) -> bool {
        let target = normalize_name(package_name);
        advisory
            .affected
            .iter()
            .any(|package| normalize_name(&package.name) == target)
    }

    /// Returns `Some` iff `locked_version` of `package_name` is affected.
    ///
    /// Package names are compared after PEP 503 normalization, and every
    /// `AffectedPackage` entry with a matching name is considered. A version
    /// is affected when it lies in any range, or appears in an explicit
    /// `versions` list. Ranges containing an unparseable PEP 440 string are
    /// skipped rather than treated as a match. When `locked_version` itself is
    /// unparseable, only the explicit `versions` list (string equality) can
    /// match.
    pub fn match_package(
        advisory: &Advisory,
        package_name: &str,
        locked_version: &str,
    ) -> Option<AdvisoryMatch> {
        let target = normalize_name(package_name);
        let locked = parse_version(locked_version);
        let mut affected = false;
        let mut fixed: Option<(Version, &str)> = None;

        for package in advisory
            .affected
            .iter()
            .filter(|package| normalize_name(&package.name) == target)
        {
            if package
                .versions
                .iter()
                .any(|listed| versions_equal(listed, locked_version, locked.as_ref()))
            {
                affected = true;
            }

            let Some(locked) = locked.as_ref() else {
                continue;
            };
            for range in &package.ranges {
                if range_contains(range, locked) != Some(true) {
                    continue;
                }
                affected = true;
                // A matched range without `fixed` does not veto a fix offered by
                // another matched range: the smallest fix among them is reported.
                let Some((raw, candidate)) = range
                    .fixed
                    .as_deref()
                    .and_then(|raw| parse_version(raw).map(|version| (raw, version)))
                else {
                    continue;
                };
                if candidate > *locked
                    && fixed
                        .as_ref()
                        .is_none_or(|(current, _)| candidate < *current)
                {
                    fixed = Some((candidate, raw));
                }
            }
        }

        affected.then(|| AdvisoryMatch {
            fixed_version: fixed.map(|(_, raw)| raw.trim().to_string()),
        })
    }

    /// Derives the verdict for one package from its match result and the
    /// release status of its fixed version.
    ///
    /// A fixed version whose release status is unknown (`None`) is treated as
    /// unreleased, so an unconfirmed fix is never reported as actionable.
    pub fn verdict(
        matched: Option<&AdvisoryMatch>,
        fix_status: Option<ReleaseStatus>,
    ) -> IncidentVerdict {
        match matched {
            None => IncidentVerdict::NotAffected,
            Some(AdvisoryMatch {
                fixed_version: None,
            }) => IncidentVerdict::AffectedNoFix,
            Some(_) => match fix_status {
                Some(ReleaseStatus::Released) => IncidentVerdict::AffectedFixReleased,
                Some(ReleaseStatus::Yanked | ReleaseStatus::NotFound) | None => {
                    IncidentVerdict::AffectedFixUnreleased
                }
            },
        }
    }

    /// Returns the most actionable verdict:
    /// `AffectedFixReleased` > `AffectedFixUnreleased` = `AffectedNoFix` >
    /// `NotAffected`. When both "unreleased" kinds are present,
    /// `AffectedFixUnreleased` wins as the more specific one. An empty slice
    /// yields `NotAffected`.
    pub fn overall(verdicts: &[IncidentVerdict]) -> IncidentVerdict {
        verdicts
            .iter()
            .copied()
            .max_by_key(|verdict| rank(*verdict))
            .unwrap_or(IncidentVerdict::NotAffected)
    }
}

/// Precedence used by `overall`; higher is more actionable.
fn rank(verdict: IncidentVerdict) -> u8 {
    match verdict {
        IncidentVerdict::NotAffected => 0,
        IncidentVerdict::AffectedNoFix => 1,
        IncidentVerdict::AffectedFixUnreleased => 2,
        IncidentVerdict::AffectedFixReleased => 3,
    }
}

/// PEP 503 name normalization: lowercase, and runs of `-`, `_`, `.` collapse
/// to a single `-`. Surrounding whitespace is ignored.
pub fn normalize_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_was_separator = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !previous_was_separator {
                normalized.push('-');
            }
            previous_was_separator = true;
        } else {
            normalized.push(c.to_ascii_lowercase());
            previous_was_separator = false;
        }
    }
    normalized
}

fn parse_version(raw: &str) -> Option<Version> {
    Version::from_str(raw.trim()).ok()
}

/// Compares an explicitly listed version against the locked version: by PEP
/// 440 equality when both parse (so `2.0` equals `2.0.0`), otherwise by exact
/// trimmed string equality.
fn versions_equal(listed: &str, locked_raw: &str, locked: Option<&Version>) -> bool {
    match (parse_version(listed), locked) {
        (Some(listed), Some(locked)) => listed == *locked,
        _ => listed.trim() == locked_raw.trim(),
    }
}

/// Returns whether `version` lies in `range`, or `None` when the range holds
/// an unparseable bound and cannot be evaluated.
fn range_contains(range: &AffectedRange, version: &Version) -> Option<bool> {
    let above_lower = match range.introduced.as_deref().map(str::trim) {
        None | Some("0") => true,
        Some(introduced) => *version >= parse_version(introduced)?,
    };
    let below_upper = if let Some(fixed) = range.fixed.as_deref() {
        *version < parse_version(fixed)?
    } else if let Some(last_affected) = range.last_affected.as_deref() {
        *version <= parse_version(last_affected)?
    } else {
        true
    };
    Some(above_lower && below_upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::advisory::AffectedPackage;

    fn range(
        introduced: Option<&str>,
        fixed: Option<&str>,
        last_affected: Option<&str>,
    ) -> AffectedRange {
        AffectedRange {
            introduced: introduced.map(str::to_string),
            fixed: fixed.map(str::to_string),
            last_affected: last_affected.map(str::to_string),
        }
    }

    fn package(name: &str, ranges: Vec<AffectedRange>, versions: &[&str]) -> AffectedPackage {
        AffectedPackage {
            name: name.to_string(),
            ranges,
            versions: versions.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn advisory(affected: Vec<AffectedPackage>) -> Advisory {
        Advisory {
            id: "GHSA-test".to_string(),
            aliases: vec![],
            summary: None,
            severity: None,
            affected,
        }
    }

    fn fixed_of(advisory: &Advisory, name: &str, version: &str) -> Option<Option<String>> {
        AdvisoryRangeMatcher::match_package(advisory, name, version).map(|m| m.fixed_version)
    }

    fn requests_advisory() -> Advisory {
        advisory(vec![package(
            "requests",
            vec![range(Some("2.3.0"), Some("2.31.0"), None)],
            &[],
        )])
    }

    #[test]
    fn test_names_package_uses_pep503_normalization() {
        let advisory = advisory(vec![package("Flask_Login", vec![], &["0.1"])]);

        assert!(AdvisoryRangeMatcher::names_package(
            &advisory,
            "flask-login"
        ));
        assert!(AdvisoryRangeMatcher::names_package(
            &advisory,
            "Flask.Login"
        ));
        assert!(!AdvisoryRangeMatcher::names_package(&advisory, "flask"));
    }

    #[test]
    fn test_names_package_false_for_empty_affected() {
        assert!(!AdvisoryRangeMatcher::names_package(
            &advisory(vec![]),
            "requests"
        ));
    }

    #[test]
    fn test_match_package_introduced_fixed_affected_with_fixed_version() {
        assert_eq!(
            fixed_of(&requests_advisory(), "requests", "2.25.0"),
            Some(Some("2.31.0".to_string()))
        );
    }

    #[test]
    fn test_match_package_fixed_version_is_exclusive_upper_bound() {
        assert_eq!(fixed_of(&requests_advisory(), "requests", "2.31.0"), None);
    }

    #[test]
    fn test_match_package_introduced_is_inclusive_lower_bound() {
        let advisory = requests_advisory();
        assert!(fixed_of(&advisory, "requests", "2.3.0").is_some());
        assert_eq!(fixed_of(&advisory, "requests", "2.2.0"), None);
    }

    #[test]
    fn test_match_package_introduced_zero_means_from_beginning() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(Some("0"), Some("1.5"), None)],
            &[],
        )]);
        assert_eq!(
            fixed_of(&advisory, "foo", "0.1"),
            Some(Some("1.5".to_string()))
        );
    }

    #[test]
    fn test_match_package_introduced_none_means_from_beginning() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(None, Some("1.5"), None)],
            &[],
        )]);
        assert!(fixed_of(&advisory, "foo", "0.1").is_some());
    }

    #[test]
    fn test_match_package_last_affected_is_inclusive_and_has_no_fix() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(Some("1.0"), None, Some("1.4"))],
            &[],
        )]);
        assert_eq!(fixed_of(&advisory, "foo", "1.4"), Some(None));
        assert_eq!(fixed_of(&advisory, "foo", "1.4.1"), None);
    }

    #[test]
    fn test_match_package_open_ended_range_has_no_fix() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(Some("1.0"), None, None)],
            &[],
        )]);
        assert_eq!(fixed_of(&advisory, "foo", "99.0"), Some(None));
    }

    #[test]
    fn test_match_package_fixed_takes_precedence_over_last_affected() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(Some("1.0"), Some("1.2"), Some("1.5"))],
            &[],
        )]);
        assert_eq!(fixed_of(&advisory, "foo", "1.3"), None);
        assert_eq!(
            fixed_of(&advisory, "foo", "1.1"),
            Some(Some("1.2".to_string()))
        );
    }

    #[test]
    fn test_match_package_explicit_versions_list() {
        let advisory = advisory(vec![package("foo", vec![], &["1.0", "2.0"])]);
        assert_eq!(fixed_of(&advisory, "foo", "1.0"), Some(None));
        assert_eq!(fixed_of(&advisory, "foo", "2.0.0"), Some(None));
        assert_eq!(fixed_of(&advisory, "foo", "1.5"), None);
    }

    #[test]
    fn test_match_package_multi_range_backport_selects_fix_of_matched_range() {
        let advisory = advisory(vec![package(
            "foo",
            vec![
                range(Some("1.0"), Some("1.4.2"), None),
                range(Some("2.0"), Some("2.3.1"), None),
            ],
            &[],
        )]);
        assert_eq!(
            fixed_of(&advisory, "foo", "2.1.0"),
            Some(Some("2.3.1".to_string()))
        );
        assert_eq!(
            fixed_of(&advisory, "foo", "1.2"),
            Some(Some("1.4.2".to_string()))
        );
        assert_eq!(fixed_of(&advisory, "foo", "1.5"), None);
    }

    #[test]
    fn test_match_package_overlapping_ranges_select_smallest_fix() {
        let advisory = advisory(vec![package(
            "foo",
            vec![
                range(Some("1.0"), Some("3.0"), None),
                range(Some("1.0"), Some("2.0"), None),
            ],
            &[],
        )]);
        assert_eq!(
            fixed_of(&advisory, "foo", "1.5"),
            Some(Some("2.0".to_string()))
        );
    }

    #[test]
    fn test_match_package_name_uses_pep503_normalization() {
        let advisory = advisory(vec![
            package("Requests", vec![range(None, Some("2.0"), None)], &[]),
            package("zope.interface", vec![range(None, Some("2.0"), None)], &[]),
            package("a--_b", vec![range(None, Some("2.0"), None)], &[]),
        ]);
        assert!(fixed_of(&advisory, "requests", "1.0").is_some());
        assert!(fixed_of(&advisory, "zope_interface", "1.0").is_some());
        assert!(fixed_of(&advisory, "A-B", "1.0").is_some());
        assert_eq!(fixed_of(&advisory, "urllib3", "1.0"), None);
    }

    #[test]
    fn test_match_package_aggregates_entries_with_same_normalized_name() {
        let advisory = advisory(vec![
            package(
                "foo-bar",
                vec![range(Some("1.0"), Some("1.4.2"), None)],
                &[],
            ),
            package(
                "Foo_Bar",
                vec![range(Some("2.0"), Some("2.3.1"), None)],
                &[],
            ),
        ]);
        assert_eq!(
            fixed_of(&advisory, "foo-bar", "2.1.0"),
            Some(Some("2.3.1".to_string()))
        );
    }

    #[test]
    fn test_match_package_invalid_range_bound_is_skipped_not_matched() {
        let advisory = advisory(vec![package(
            "foo",
            vec![
                range(Some("not-a-version"), Some("9.0"), None),
                range(Some("0"), Some("also bad"), None),
                range(Some("2.0"), Some("2.3.1"), None),
            ],
            &[],
        )]);
        assert_eq!(fixed_of(&advisory, "foo", "1.0"), None);
        assert_eq!(
            fixed_of(&advisory, "foo", "2.1"),
            Some(Some("2.3.1".to_string()))
        );
    }

    #[test]
    fn test_match_package_unparseable_locked_version_only_matches_versions_list() {
        let advisory = advisory(vec![package(
            "foo",
            vec![range(Some("0"), Some("9.0"), None)],
            &["weird-build"],
        )]);
        assert_eq!(fixed_of(&advisory, "foo", "weird-build"), Some(None));
        assert_eq!(fixed_of(&advisory, "foo", "other-weird"), None);
    }

    #[test]
    fn test_match_package_empty_advisory_is_not_affected() {
        assert_eq!(fixed_of(&advisory(vec![]), "foo", "1.0"), None);
        let no_ranges = advisory(vec![package("foo", vec![], &[])]);
        assert_eq!(fixed_of(&no_ranges, "foo", "1.0"), None);
    }

    fn with_fix() -> AdvisoryMatch {
        AdvisoryMatch {
            fixed_version: Some("2.31.0".to_string()),
        }
    }

    #[test]
    fn test_verdict_not_matched_is_not_affected() {
        assert_eq!(
            AdvisoryRangeMatcher::verdict(None, Some(ReleaseStatus::Released)),
            IncidentVerdict::NotAffected
        );
    }

    #[test]
    fn test_verdict_matched_without_fix_is_no_fix() {
        let matched = AdvisoryMatch {
            fixed_version: None,
        };
        assert_eq!(
            AdvisoryRangeMatcher::verdict(Some(&matched), None),
            IncidentVerdict::AffectedNoFix
        );
    }

    #[test]
    fn test_verdict_released_fix() {
        assert_eq!(
            AdvisoryRangeMatcher::verdict(Some(&with_fix()), Some(ReleaseStatus::Released)),
            IncidentVerdict::AffectedFixReleased
        );
    }

    #[test]
    fn test_verdict_yanked_fix_is_unreleased() {
        assert_eq!(
            AdvisoryRangeMatcher::verdict(Some(&with_fix()), Some(ReleaseStatus::Yanked)),
            IncidentVerdict::AffectedFixUnreleased
        );
    }

    #[test]
    fn test_verdict_not_found_fix_is_unreleased() {
        assert_eq!(
            AdvisoryRangeMatcher::verdict(Some(&with_fix()), Some(ReleaseStatus::NotFound)),
            IncidentVerdict::AffectedFixUnreleased
        );
    }

    #[test]
    fn test_verdict_unknown_release_status_is_unreleased() {
        assert_eq!(
            AdvisoryRangeMatcher::verdict(Some(&with_fix()), None),
            IncidentVerdict::AffectedFixUnreleased
        );
    }

    #[test]
    fn test_overall_empty_is_not_affected() {
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[]),
            IncidentVerdict::NotAffected
        );
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[IncidentVerdict::NotAffected]),
            IncidentVerdict::NotAffected
        );
    }

    #[test]
    fn test_overall_no_fix_beats_not_affected() {
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[
                IncidentVerdict::AffectedNoFix,
                IncidentVerdict::NotAffected
            ]),
            IncidentVerdict::AffectedNoFix
        );
    }

    #[test]
    fn test_overall_fix_unreleased_wins_tie_with_no_fix_regardless_of_order() {
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[
                IncidentVerdict::AffectedNoFix,
                IncidentVerdict::AffectedFixUnreleased
            ]),
            IncidentVerdict::AffectedFixUnreleased
        );
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[
                IncidentVerdict::AffectedFixUnreleased,
                IncidentVerdict::AffectedNoFix
            ]),
            IncidentVerdict::AffectedFixUnreleased
        );
    }

    #[test]
    fn test_overall_fix_released_beats_everything() {
        assert_eq!(
            AdvisoryRangeMatcher::overall(&[
                IncidentVerdict::NotAffected,
                IncidentVerdict::AffectedFixUnreleased,
                IncidentVerdict::AffectedFixReleased,
                IncidentVerdict::AffectedNoFix,
            ]),
            IncidentVerdict::AffectedFixReleased
        );
    }

    #[test]
    fn test_match_package_trims_fixed_version() {
        let advisory = advisory(vec![package(
            "requests",
            vec![range(Some("0"), Some(" 2.31.0 \n"), None)],
            &[],
        )]);

        assert_eq!(
            fixed_of(&advisory, "requests", "2.25.0"),
            Some(Some("2.31.0".to_string()))
        );
    }

    #[test]
    fn test_normalize_name_is_pep503() {
        assert_eq!(normalize_name(" Flask__Login.Ext "), "flask-login-ext");
        assert_eq!(normalize_name("requests"), "requests");
    }
}
