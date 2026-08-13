use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity};

/// Extracts numeric CVSS score from CVSS vector string
///
/// Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> Some(9.8)
///
/// Note: This is a simplified implementation that extracts the score from
/// the vector components. For the initial implementation, we calculate
/// the score based on the metrics in the vector string.
pub(super) fn parse_cvss_score(cvss_vector: &str) -> Option<CvssScore> {
    // CVSS v3.1 metric values and their scores
    // This is a simplified scoring algorithm based on the Base Score formula

    // Parse metrics from vector string
    let metrics: std::collections::HashMap<&str, &str> = cvss_vector
        .split('/')
        .skip(1) // Skip "CVSS:3.1" or "CVSS:3.0"
        .filter_map(|part| {
            let mut split = part.split(':');
            Some((split.next()?, split.next()?))
        })
        .collect();

    // Extract metric values
    let av = metrics.get("AV")?;
    let ac = metrics.get("AC")?;
    let pr = metrics.get("PR")?;
    let ui = metrics.get("UI")?;
    let s = metrics.get("S")?;
    let c = metrics.get("C")?;
    let i = metrics.get("I")?;
    let a = metrics.get("A")?;

    // Calculate exploitability sub-score
    let av_score = match *av {
        "N" => 0.85, // Network
        "A" => 0.62, // Adjacent
        "L" => 0.55, // Local
        "P" => 0.2,  // Physical
        _ => return None,
    };

    let ac_score = match *ac {
        "L" => 0.77, // Low
        "H" => 0.44, // High
        _ => return None,
    };

    let pr_score = match (*pr, *s) {
        ("N", _) => 0.85,   // None
        ("L", "U") => 0.62, // Low, Unchanged
        ("L", "C") => 0.68, // Low, Changed
        ("H", "U") => 0.27, // High, Unchanged
        ("H", "C") => 0.5,  // High, Changed
        _ => return None,
    };

    let ui_score = match *ui {
        "N" => 0.85, // None
        "R" => 0.62, // Required
        _ => return None,
    };

    // Calculate impact sub-score
    let c_score = match *c {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    let i_score = match *i {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    let a_score = match *a {
        "N" => 0.0,  // None
        "L" => 0.22, // Low
        "H" => 0.56, // High
        _ => return None,
    };

    // Calculate ISS (Impact Sub-Score)
    let iss = 1.0_f64 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score));

    // Calculate Impact
    let impact = if *s == "U" {
        6.42 * iss
    } else {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02_f64).powi(15)
    };

    // Calculate Exploitability
    let exploitability = 8.22 * av_score * ac_score * pr_score * ui_score;

    // Calculate Base Score
    let base_score = if impact <= 0.0 {
        0.0
    } else if *s == "U" {
        f64::min(impact + exploitability, 10.0)
    } else {
        f64::min(1.08 * (impact + exploitability), 10.0)
    };

    // Round up to one decimal place
    let rounded_score = (base_score * 10.0).ceil() / 10.0;

    CvssScore::new(rounded_score as f32).ok()
}

/// Parses severity string from OSV database_specific field
///
/// Maps OSV severity strings to our Severity enum:
/// - "CRITICAL" -> Severity::Critical
/// - "HIGH" -> Severity::High
/// - "MODERATE" or "MEDIUM" -> Severity::Medium
/// - "LOW" -> Severity::Low
/// - Unknown values -> Severity::None
pub(super) fn parse_severity_string(severity: &str) -> Severity {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cvss_score_critical() {
        // High severity example (network, low complexity, no privileges, no interaction)
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be around 9.8 (Critical)
        assert!(score.value() >= 9.0 && score.value() <= 10.0);
    }

    #[test]
    fn test_parse_cvss_score_high() {
        // High severity example
        let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be around 8.8 (High)
        assert!(score.value() >= 7.0 && score.value() < 9.0);
    }

    #[test]
    fn test_parse_cvss_score_medium() {
        // Medium severity example
        let vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be in the Medium range (4.0-6.9)
        assert!(score.value() >= 4.0 && score.value() < 7.0);
    }

    #[test]
    fn test_parse_cvss_score_low() {
        // Low severity example
        let vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        // This should be in the Low range (0.1-3.9)
        assert!(score.value() > 0.0 && score.value() < 4.0);
    }

    #[test]
    fn test_parse_cvss_score_none() {
        // No impact
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        let score = parse_cvss_score(vector);
        assert!(score.is_some());
        let score = score.unwrap();
        assert_eq!(score.value(), 0.0);
    }

    #[test]
    fn test_parse_cvss_score_invalid() {
        let vector = "invalid vector";
        let score = parse_cvss_score(vector);
        assert!(score.is_none());
    }

    #[test]
    fn test_parse_severity_string() {
        assert_eq!(parse_severity_string("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity_string("critical"), Severity::Critical);
        assert_eq!(parse_severity_string("HIGH"), Severity::High);
        assert_eq!(parse_severity_string("high"), Severity::High);
        assert_eq!(parse_severity_string("MODERATE"), Severity::Medium);
        assert_eq!(parse_severity_string("moderate"), Severity::Medium);
        assert_eq!(parse_severity_string("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity_string("medium"), Severity::Medium);
        assert_eq!(parse_severity_string("LOW"), Severity::Low);
        assert_eq!(parse_severity_string("low"), Severity::Low);
        assert_eq!(parse_severity_string("UNKNOWN"), Severity::None);
        assert_eq!(parse_severity_string(""), Severity::None);
    }
}
