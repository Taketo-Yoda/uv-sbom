//! Domain model for a single OSV advisory, used by `--incident` mode.
//!
//! These are plain value objects with no I/O. The OSV adapter maps the wire
//! format into them, keeping only `ECOSYSTEM` ranges and flattening each
//! `introduced` → `fixed` / `last_affected` interval into one `AffectedRange`.

use super::vulnerability::Severity;

/// A single security advisory (e.g. a GHSA or PYSEC entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Option<Severity>,
    pub affected: Vec<AffectedPackage>,
}

/// One package affected by an advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedPackage {
    /// Package name as published in the advisory (normalized when matched).
    pub name: String,
    /// `ECOSYSTEM` ranges only, one entry per flattened interval.
    pub ranges: Vec<AffectedRange>,
    /// Explicitly enumerated affected versions.
    pub versions: Vec<String>,
}

/// One affected interval.
///
/// `introduced` of `None` or `"0"` means "from the beginning". The upper
/// bound is `fixed` (exclusive) or `last_affected` (inclusive); when both are
/// present, `fixed` takes precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

/// Release status of a fixed version on the package index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStatus {
    /// Published and installable.
    Released,
    /// Published but yanked.
    Yanked,
    /// Not published on the index (a failed lookup is not represented here).
    NotFound,
}

/// Incident-mode verdict for a package (or, via `overall`, a whole project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentVerdict {
    /// The locked version is outside every affected range.
    NotAffected,
    /// Affected, and the fixed version is released.
    AffectedFixReleased,
    /// Affected, and a fixed version is named but not (yet) installable.
    AffectedFixUnreleased,
    /// Affected, and the advisory names no fixed version.
    AffectedNoFix,
}
