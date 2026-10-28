//! What `--incident` evaluates: an advisory ID, or a manual version-range spec
//! for an advisory not yet in OSV (#963).
//!
//! A manual spec such as `foo>=2.0,<2.3.2` is parsed here and converted into a
//! synthetic `Advisory`, so the same `AdvisoryRangeMatcher`, verdicts, and
//! release/simulation flow apply to both forms. Parsing is pure; errors are
//! typed and carry structured data only, and the CLI renders them in the
//! user's locale (#832).

use super::advisory::{Advisory, AffectedPackage, AffectedRange};
use super::package::normalize_name;
use pep440_rs::{Operator, Version, VersionSpecifiers};
use std::str::FromStr;

/// The incident to evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentTarget {
    /// An advisory ID (GHSA-, PYSEC-, CVE-, OSV- or MAL-) looked up in OSV.
    AdvisoryId(String),
    /// A user-supplied affected range; no OSV lookup is made.
    ManualSpec(ManualAffectedSpec),
}

/// A user-supplied affected range for one package, e.g. `foo>=2.0,<2.3.2`.
///
/// `>=` maps to `introduced`, `<` to `fixed`, and `<=` to `last_affected`, the
/// same OSV range semantics the advisory path uses (so, as with OSV ranges, a
/// pre-release of the fixed version such as `2.3.2rc1` counts as affected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualAffectedSpec {
    /// The trimmed input, used as the report's advisory ID.
    pub spec: String,
    /// PEP 503-normalized package name.
    pub package_name: String,
    /// Lower bound (`>=`), inclusive.
    pub introduced: Option<String>,
    /// Upper bound (`<`), exclusive; treated as the fixed version.
    pub fixed: Option<String>,
    /// Upper bound (`<=`), inclusive; no fixed version is known.
    pub last_affected: Option<String>,
}

/// Why a manual spec was rejected. The English `Display` text is the library
/// contract; the CLI renders a localized message from the variant's data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManualSpecError {
    /// The input is empty or whitespace only.
    #[error("the value is empty")]
    Empty,
    /// The input starts with a specifier, e.g. `<2.0`.
    #[error("no package name was given")]
    MissingPackageName,
    /// The name does not start and end with a letter or digit, e.g. `foo-<2`.
    #[error("'{name}' is not a valid package name")]
    InvalidPackageName { name: String },
    /// A bare package name, e.g. `requests`.
    #[error("no version range was given for '{package}'")]
    MissingSpecifier { package: String },
    /// The specifiers are not valid PEP 440, e.g. `<abc` or `<2.0,`.
    #[error("could not parse the version range '{specifiers}'")]
    InvalidSpecifiers { specifiers: String },
    /// An operator other than `>=`, `<`, `<=`, e.g. `==2.25.0` or `>2.0`.
    #[error("'{specifier}' uses an unsupported operator; only >=, <, and <= are allowed")]
    UnsupportedOperator { specifier: String },
    /// More than one `>=`.
    #[error("only one lower bound (>=) is allowed")]
    MultipleLowerBounds,
    /// More than one of `<` / `<=`, including `<` together with `<=`.
    #[error("only one upper bound (< or <=) is allowed")]
    MultipleUpperBounds,
    /// The bounds exclude every version, e.g. `>=2.3,<2.0`.
    #[error("the range '{specifiers}' contains no versions")]
    EmptyRange { specifiers: String },
}

impl ManualAffectedSpec {
    /// Parses `<package><specifiers>`, where the specifiers are one or more
    /// comma-separated `>=`, `<`, or `<=` PEP 440 specifiers. Whitespace
    /// around the name, operators, and versions is ignored.
    ///
    /// # Errors
    /// Returns the `ManualSpecError` variant describing the first problem found.
    pub fn parse(input: &str) -> Result<Self, ManualSpecError> {
        let spec = input.trim();
        if spec.is_empty() {
            return Err(ManualSpecError::Empty);
        }
        let (name, tail) = split_name(spec)?;
        let specifiers =
            VersionSpecifiers::from_str(tail).map_err(|_| ManualSpecError::InvalidSpecifiers {
                specifiers: tail.to_string(),
            })?;
        let (lower, upper) = classify_bounds(&specifiers)?;
        ensure_non_empty(lower.as_ref(), upper.as_ref(), tail)?;

        let (fixed, last_affected) = match upper {
            Some((Operator::LessThan, version)) => (Some(version.to_string()), None),
            Some((_, version)) => (None, Some(version.to_string())),
            None => (None, None),
        };
        Ok(Self {
            spec: spec.to_string(),
            package_name: normalize_name(name),
            introduced: lower.map(|version| version.to_string()),
            fixed,
            last_affected,
        })
    }

    /// The synthetic advisory evaluated in place of an OSV record: the spec as
    /// its ID, no aliases/summary/severity, and one package with one range. A
    /// missing lower bound becomes `introduced: "0"`, as in OSV.
    pub fn to_advisory(&self) -> Advisory {
        Advisory {
            id: self.spec.clone(),
            aliases: Vec::new(),
            summary: None,
            severity: None,
            affected: vec![AffectedPackage {
                name: self.package_name.clone(),
                ranges: vec![AffectedRange {
                    introduced: Some(self.introduced.clone().unwrap_or_else(|| "0".to_string())),
                    fixed: self.fixed.clone(),
                    last_affected: self.last_affected.clone(),
                }],
                versions: Vec::new(),
            }],
        }
    }
}

/// An upper bound: `<` (exclusive, the fixed version) or `<=` (inclusive).
type UpperBound = (Operator, Version);

/// Splits a trimmed, non-empty spec into its package name (the leading run of
/// PEP 508 name characters) and the trimmed, non-empty specifier text.
fn split_name(spec: &str) -> Result<(&str, &str), ManualSpecError> {
    let name_end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(spec.len());
    let (name, tail) = spec.split_at(name_end);
    if name.is_empty() {
        return Err(ManualSpecError::MissingPackageName);
    }
    let alphanumeric_ends = name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    if !alphanumeric_ends {
        return Err(ManualSpecError::InvalidPackageName {
            name: name.to_string(),
        });
    }
    let tail = tail.trim();
    if tail.is_empty() {
        return Err(ManualSpecError::MissingSpecifier {
            package: name.to_string(),
        });
    }
    Ok((name, tail))
}

/// Sorts the specifiers into at most one lower bound (`>=`) and at most one
/// upper bound (`<` or `<=`), rejecting every other operator.
fn classify_bounds(
    specifiers: &VersionSpecifiers,
) -> Result<(Option<Version>, Option<UpperBound>), ManualSpecError> {
    let mut lower: Option<Version> = None;
    let mut upper: Option<UpperBound> = None;
    for specifier in specifiers.iter() {
        match specifier.operator() {
            Operator::GreaterThanEqual => {
                if lower.replace(specifier.version().clone()).is_some() {
                    return Err(ManualSpecError::MultipleLowerBounds);
                }
            }
            op @ (Operator::LessThan | Operator::LessThanEqual) => {
                if upper.replace((*op, specifier.version().clone())).is_some() {
                    return Err(ManualSpecError::MultipleUpperBounds);
                }
            }
            _ => {
                return Err(ManualSpecError::UnsupportedOperator {
                    specifier: specifier.to_string(),
                })
            }
        }
    }
    Ok((lower, upper))
}

/// Rejects bounds that exclude every version (`>=2.3,<2.0`, `>=2.0,<2.0`,
/// `>=2.1,<=2.0`), which would otherwise silently report "not affected".
/// `specifiers` is the original text, for the error.
fn ensure_non_empty(
    lower: Option<&Version>,
    upper: Option<&UpperBound>,
    specifiers: &str,
) -> Result<(), ManualSpecError> {
    let empty = match (lower, upper) {
        (Some(low), Some((Operator::LessThan, high))) => low >= high,
        (Some(low), Some((_, high))) => low > high,
        _ => false,
    };
    if empty {
        return Err(ManualSpecError::EmptyRange {
            specifiers: specifiers.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::advisory::IncidentVerdict;
    use crate::sbom_generation::domain::services::advisory_range_matcher::AdvisoryRangeMatcher;

    fn parse(input: &str) -> ManualAffectedSpec {
        ManualAffectedSpec::parse(input).unwrap()
    }

    fn bounds(spec: &ManualAffectedSpec) -> (Option<&str>, Option<&str>, Option<&str>) {
        (
            spec.introduced.as_deref(),
            spec.fixed.as_deref(),
            spec.last_affected.as_deref(),
        )
    }

    #[test]
    fn test_parse_less_than_is_fixed() {
        assert_eq!(bounds(&parse("foo<2.3.2")), (None, Some("2.3.2"), None));
    }

    #[test]
    fn test_parse_less_than_equal_is_last_affected() {
        assert_eq!(bounds(&parse("foo<=2.3.1")), (None, None, Some("2.3.1")));
    }

    #[test]
    fn test_parse_greater_than_equal_is_introduced() {
        assert_eq!(bounds(&parse("foo>=2.0")), (Some("2.0"), None, None));
    }

    #[test]
    fn test_parse_combined_bounds() {
        assert_eq!(
            bounds(&parse("foo>=2.0,<2.3.2")),
            (Some("2.0"), Some("2.3.2"), None)
        );
        assert_eq!(
            bounds(&parse("foo>=2.0,<=2.3.1")),
            (Some("2.0"), None, Some("2.3.1"))
        );
    }

    #[test]
    fn test_parse_order_of_specifiers_does_not_matter() {
        assert_eq!(
            bounds(&parse("foo<2.3.2,>=2.0")),
            (Some("2.0"), Some("2.3.2"), None)
        );
    }

    #[test]
    fn test_parse_normalizes_package_name() {
        assert_eq!(parse("Foo_Bar.baz<1").package_name, "foo-bar-baz");
    }

    #[test]
    fn test_parse_tolerates_whitespace_and_keeps_trimmed_spec() {
        let spec = parse("  requests >= 2.0 , < 2.3.2  ");
        assert_eq!(spec.package_name, "requests");
        assert_eq!(bounds(&spec), (Some("2.0"), Some("2.3.2"), None));
        assert_eq!(spec.spec, "requests >= 2.0 , < 2.3.2");
    }

    #[test]
    fn test_parse_rejects_unsupported_operators() {
        for (input, specifier) in [
            ("requests==2.25.0", "==2.25.0"),
            ("requests!=1.0", "!=1.0"),
            ("requests~=2.0", "~=2.0"),
            ("requests>2.0", ">2.0"),
            ("requests===1.0", "===1.0"),
            ("requests==2.*", "==2.*"),
        ] {
            assert_eq!(
                ManualAffectedSpec::parse(input),
                Err(ManualSpecError::UnsupportedOperator {
                    specifier: specifier.to_string()
                }),
                "{input}"
            );
        }
    }

    #[test]
    fn test_parse_rejects_missing_specifier() {
        assert_eq!(
            ManualAffectedSpec::parse("requests"),
            Err(ManualSpecError::MissingSpecifier {
                package: "requests".to_string()
            })
        );
    }

    #[test]
    fn test_parse_rejects_empty_input() {
        assert_eq!(ManualAffectedSpec::parse("  "), Err(ManualSpecError::Empty));
    }

    #[test]
    fn test_parse_rejects_missing_package_name() {
        assert_eq!(
            ManualAffectedSpec::parse("<2.0"),
            Err(ManualSpecError::MissingPackageName)
        );
    }

    #[test]
    fn test_parse_rejects_invalid_package_name() {
        assert_eq!(
            ManualAffectedSpec::parse("foo-<2"),
            Err(ManualSpecError::InvalidPackageName {
                name: "foo-".to_string()
            })
        );
    }

    #[test]
    fn test_parse_rejects_two_lower_bounds() {
        assert_eq!(
            ManualAffectedSpec::parse("foo>=1,>=2"),
            Err(ManualSpecError::MultipleLowerBounds)
        );
    }

    #[test]
    fn test_parse_rejects_two_upper_bounds() {
        for input in ["foo<1,<2", "foo<=1,<=2", "foo<1,<=2"] {
            assert_eq!(
                ManualAffectedSpec::parse(input),
                Err(ManualSpecError::MultipleUpperBounds),
                "{input}"
            );
        }
    }

    #[test]
    fn test_parse_rejects_invalid_versions_and_syntax() {
        for (input, specifiers) in [
            ("foo<abc", "<abc"),
            ("foo<2.0,", "<2.0,"),
            ("foo[extra]<2", "[extra]<2"),
        ] {
            assert_eq!(
                ManualAffectedSpec::parse(input),
                Err(ManualSpecError::InvalidSpecifiers {
                    specifiers: specifiers.to_string()
                }),
                "{input}"
            );
        }
    }

    #[test]
    fn test_parse_rejects_empty_range() {
        for (input, specifiers) in [
            ("foo>=2.3,<2.0", ">=2.3,<2.0"),
            ("foo>=2.0,<2.0", ">=2.0,<2.0"),
            ("foo>=2.1,<=2.0", ">=2.1,<=2.0"),
        ] {
            assert_eq!(
                ManualAffectedSpec::parse(input),
                Err(ManualSpecError::EmptyRange {
                    specifiers: specifiers.to_string()
                }),
                "{input}"
            );
        }
    }

    #[test]
    fn test_parse_accepts_single_version_inclusive_range() {
        assert_eq!(
            bounds(&parse("foo>=2.0,<=2.0")),
            (Some("2.0"), None, Some("2.0"))
        );
    }

    #[test]
    fn test_to_advisory_missing_lower_bound_becomes_zero() {
        let advisory = parse("requests<2.31.0").to_advisory();
        assert_eq!(advisory.id, "requests<2.31.0");
        assert!(advisory.aliases.is_empty());
        assert_eq!(advisory.summary, None);
        assert_eq!(advisory.severity, None);
        assert_eq!(
            advisory.affected,
            vec![AffectedPackage {
                name: "requests".to_string(),
                ranges: vec![AffectedRange {
                    introduced: Some("0".to_string()),
                    fixed: Some("2.31.0".to_string()),
                    last_affected: None,
                }],
                versions: Vec::new(),
            }]
        );
    }

    #[test]
    fn test_to_advisory_keeps_lower_and_inclusive_upper_bounds() {
        let advisory = parse("foo>=2.0,<=2.3.1").to_advisory();
        assert_eq!(
            advisory.affected[0].ranges,
            vec![AffectedRange {
                introduced: Some("2.0".to_string()),
                fixed: None,
                last_affected: Some("2.3.1".to_string()),
            }]
        );
    }

    #[test]
    fn test_to_advisory_matches_through_range_matcher() {
        let matched = AdvisoryRangeMatcher::match_package(
            &parse("requests<2.31.0").to_advisory(),
            "requests",
            "2.25.0",
        );
        assert_eq!(
            matched.and_then(|m| m.fixed_version).as_deref(),
            Some("2.31.0")
        );

        let outside = AdvisoryRangeMatcher::match_package(
            &parse("requests>=2.26,<2.31.0").to_advisory(),
            "requests",
            "2.25.0",
        );
        assert!(outside.is_none());

        let no_fix = AdvisoryRangeMatcher::match_package(
            &parse("requests<=2.30.0").to_advisory(),
            "requests",
            "2.25.0",
        );
        assert_eq!(
            AdvisoryRangeMatcher::verdict(no_fix.as_ref(), None),
            IncidentVerdict::AffectedNoFix
        );
    }
}
