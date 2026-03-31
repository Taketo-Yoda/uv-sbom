//! SPDX License ID mapping for common Python package licenses
//!
//! Maps license name strings (as reported by PyPI) to their corresponding
//! SPDX license identifiers. Uses case-insensitive matching.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Lookup table mapping normalized license names to SPDX identifiers.
static LICENSE_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    let entries: Vec<(&str, &str)> = vec![
        // MIT variants
        ("mit license", "MIT"),
        ("mit", "MIT"),
        ("the mit license", "MIT"),
        ("the mit license (mit)", "MIT"),
        // Apache variants
        ("apache software license", "Apache-2.0"),
        ("apache license 2.0", "Apache-2.0"),
        ("apache license, version 2.0", "Apache-2.0"),
        ("apache 2.0", "Apache-2.0"),
        ("apache-2.0", "Apache-2.0"),
        ("apache 2", "Apache-2.0"),
        // BSD variants
        // Note: "BSD License" is intentionally omitted — ambiguous between
        // BSD-2-Clause and BSD-3-Clause.
        ("bsd 3-clause license", "BSD-3-Clause"),
        ("bsd-3-clause", "BSD-3-Clause"),
        (
            "bsd 3-clause \"new\" or \"revised\" license",
            "BSD-3-Clause",
        ),
        ("new bsd license", "BSD-3-Clause"),
        ("modified bsd license", "BSD-3-Clause"),
        ("3-clause bsd license", "BSD-3-Clause"),
        ("bsd 2-clause license", "BSD-2-Clause"),
        ("bsd-2-clause", "BSD-2-Clause"),
        ("simplified bsd license", "BSD-2-Clause"),
        ("bsd 2-clause \"simplified\" license", "BSD-2-Clause"),
        // GPL variants
        ("gnu general public license v3 (gplv3)", "GPL-3.0-only"),
        ("gpl-3.0", "GPL-3.0-only"),
        ("gpl-3.0-only", "GPL-3.0-only"),
        ("gplv3", "GPL-3.0-only"),
        (
            "gnu general public license v3 or later (gplv3+)",
            "GPL-3.0-or-later",
        ),
        ("gpl-3.0+", "GPL-3.0-or-later"),
        ("gpl-3.0-or-later", "GPL-3.0-or-later"),
        ("gnu general public license v2 (gplv2)", "GPL-2.0-only"),
        ("gpl-2.0", "GPL-2.0-only"),
        ("gpl-2.0-only", "GPL-2.0-only"),
        ("gplv2", "GPL-2.0-only"),
        (
            "gnu general public license v2 or later (gplv2+)",
            "GPL-2.0-or-later",
        ),
        ("gpl-2.0+", "GPL-2.0-or-later"),
        ("gpl-2.0-or-later", "GPL-2.0-or-later"),
        // LGPL variants
        (
            "gnu lesser general public license v3 (lgplv3)",
            "LGPL-3.0-only",
        ),
        ("lgpl-3.0", "LGPL-3.0-only"),
        ("lgpl-3.0-only", "LGPL-3.0-only"),
        ("lgplv3", "LGPL-3.0-only"),
        (
            "gnu lesser general public license v2 (lgplv2)",
            "LGPL-2.0-only",
        ),
        ("lgpl-2.1", "LGPL-2.1-only"),
        ("lgpl-2.1-only", "LGPL-2.1-only"),
        (
            "gnu lesser general public license v2 or later (lgplv2+)",
            "LGPL-2.1-or-later",
        ),
        // MPL
        ("mozilla public license 2.0", "MPL-2.0"),
        ("mozilla public license 2.0 (mpl 2.0)", "MPL-2.0"),
        ("mpl-2.0", "MPL-2.0"),
        ("mpl 2.0", "MPL-2.0"),
        // ISC
        ("isc license", "ISC"),
        ("isc license (iscl)", "ISC"),
        ("isc", "ISC"),
        // PSF / Python
        ("python software foundation license", "PSF-2.0"),
        ("psf license", "PSF-2.0"),
        ("psf-2.0", "PSF-2.0"),
        // Unlicense
        ("the unlicense", "Unlicense"),
        ("the unlicense (unlicense)", "Unlicense"),
        ("unlicense", "Unlicense"),
        // CC0
        ("cc0 1.0 universal", "CC0-1.0"),
        ("cc0-1.0", "CC0-1.0"),
        (
            "cc0 1.0 universal (cc0 1.0) public domain dedication",
            "CC0-1.0",
        ),
        // Zlib
        ("zlib license", "Zlib"),
        ("zlib", "Zlib"),
        // Eclipse
        ("eclipse public license 2.0", "EPL-2.0"),
        ("epl-2.0", "EPL-2.0"),
        // WTFPL
        ("do what the f*ck you want to public license", "WTFPL"),
        ("wtfpl", "WTFPL"),
        // Artistic
        ("artistic license 2.0", "Artistic-2.0"),
        ("artistic-2.0", "Artistic-2.0"),
    ];

    entries.into_iter().collect()
});

/// Attempts to resolve a license name to its SPDX identifier.
///
/// Strategy:
///   1. Exact match after case-folding and whitespace trim (fast path)
///   2. Strip common trailing suffixes ("License", "Licence") and retry
///   3. Return `None` (caller falls back to raw string)
pub fn get_spdx_id(license_name: &str) -> Option<String> {
    let normalized = license_name.trim().to_lowercase();

    if let Some(id) = LICENSE_MAP.get(normalized.as_str()) {
        return Some(id.to_string());
    }

    // Fuzzy pass: strip trailing "license" / "licence" and retry
    let stripped = normalized
        .trim_end_matches("license")
        .trim_end_matches("licence")
        .trim();

    if stripped != normalized {
        LICENSE_MAP.get(stripped).map(|id| id.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mit_license_variants() {
        assert_eq!(get_spdx_id("MIT License"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("MIT"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("mit license"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("The MIT License"), Some("MIT".to_string()));
    }

    #[test]
    fn test_apache_license_variants() {
        assert_eq!(
            get_spdx_id("Apache Software License"),
            Some("Apache-2.0".to_string())
        );
        assert_eq!(
            get_spdx_id("Apache License 2.0"),
            Some("Apache-2.0".to_string())
        );
        assert_eq!(get_spdx_id("Apache-2.0"), Some("Apache-2.0".to_string()));
        assert_eq!(get_spdx_id("apache 2.0"), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn test_bsd_license_variants() {
        // "BSD License" is intentionally unmapped (ambiguous between BSD-2-Clause and BSD-3-Clause)
        assert_eq!(get_spdx_id("BSD License"), None);
        assert_eq!(
            get_spdx_id("BSD-3-Clause"),
            Some("BSD-3-Clause".to_string())
        );
        assert_eq!(
            get_spdx_id("BSD 3-Clause License"),
            Some("BSD-3-Clause".to_string())
        );
        assert_eq!(
            get_spdx_id("BSD 3-Clause \"New\" or \"Revised\" License"),
            Some("BSD-3-Clause".to_string())
        );
        assert_eq!(
            get_spdx_id("BSD 2-Clause License"),
            Some("BSD-2-Clause".to_string())
        );
        assert_eq!(
            get_spdx_id("BSD 2-Clause \"Simplified\" License"),
            Some("BSD-2-Clause".to_string())
        );
    }

    #[test]
    fn test_gpl_license_variants() {
        assert_eq!(
            get_spdx_id("GNU General Public License v3 (GPLv3)"),
            Some("GPL-3.0-only".to_string())
        );
        assert_eq!(get_spdx_id("GPL-3.0"), Some("GPL-3.0-only".to_string()));
        assert_eq!(get_spdx_id("GPLv2"), Some("GPL-2.0-only".to_string()));
    }

    #[test]
    fn test_case_insensitive_matching() {
        assert_eq!(get_spdx_id("MIT LICENSE"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("mit"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("Mit License"), Some("MIT".to_string()));
        assert_eq!(
            get_spdx_id("APACHE SOFTWARE LICENSE"),
            Some("Apache-2.0".to_string())
        );
    }

    #[test]
    fn test_whitespace_trimming() {
        assert_eq!(get_spdx_id("  MIT License  "), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("\tMIT\n"), Some("MIT".to_string()));
    }

    #[test]
    fn test_lgpl_v2_maps_to_lgpl_2_0_only() {
        assert_eq!(
            get_spdx_id("GNU Lesser General Public License v2 (LGPLv2)"),
            Some("LGPL-2.0-only".to_string())
        );
    }

    #[test]
    fn test_fuzzy_suffix_strip() {
        // "Zlib License" → strip "License" → "Zlib" → exact match → "Zlib"
        assert_eq!(get_spdx_id("Zlib License"), Some("Zlib".to_string()));
        // "ISC Licence" (alternative spelling) → strip "Licence" → "ISC" → "ISC"
        assert_eq!(get_spdx_id("ISC Licence"), Some("ISC".to_string()));
        // "Artistic-2.0 License" → strip "License" → "Artistic-2.0" → exact match
        assert_eq!(
            get_spdx_id("Artistic-2.0 License"),
            Some("Artistic-2.0".to_string())
        );
        // Suffix strip should not affect entries that already have an exact match
        assert_eq!(get_spdx_id("MIT License"), Some("MIT".to_string()));
        assert_eq!(get_spdx_id("ISC License"), Some("ISC".to_string()));
        // No suffix to strip → still returns None for unknown strings
        assert_eq!(get_spdx_id("Proprietary"), None);
    }

    #[test]
    fn test_unknown_license_returns_none() {
        assert_eq!(get_spdx_id("Some Proprietary License"), None);
        assert_eq!(get_spdx_id("Custom License v1.0"), None);
        assert_eq!(get_spdx_id(""), None);
    }

    #[test]
    fn test_other_licenses() {
        assert_eq!(get_spdx_id("ISC License"), Some("ISC".to_string()));
        assert_eq!(
            get_spdx_id("Mozilla Public License 2.0"),
            Some("MPL-2.0".to_string())
        );
        assert_eq!(get_spdx_id("The Unlicense"), Some("Unlicense".to_string()));
        assert_eq!(
            get_spdx_id("CC0 1.0 Universal"),
            Some("CC0-1.0".to_string())
        );
    }
}
