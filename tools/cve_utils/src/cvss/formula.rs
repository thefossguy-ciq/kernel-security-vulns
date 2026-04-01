// SPDX-License-Identifier: GPL-2.0-only
//
// CVSS v3.1 base score calculation per FIRST.org specification.
// https://www.first.org/cvss/v3-1/specification-document
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use super::metrics::{CvssMetrics, Scope};

pub struct ScoreResult {
    pub score: f64,
    pub severity: String,
    pub iss: f64,
    pub impact: f64,
    pub exploitability: f64,
}

/// Roundup function per CVSS v3.1 spec Appendix A.
/// Returns the smallest number, specified to 1 decimal place,
/// that is equal to or higher than its input.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10000 == 0 {
        (int_input as f64) / 100_000.0
    } else {
        ((int_input / 10000 + 1) * 10000) as f64 / 100_000.0
    }
}

fn severity_from_score(score: f64) -> String {
    if score == 0.0 {
        "NONE".to_string()
    } else if score <= 3.9 {
        "LOW".to_string()
    } else if score <= 6.9 {
        "MEDIUM".to_string()
    } else if score <= 8.9 {
        "HIGH".to_string()
    } else {
        "CRITICAL".to_string()
    }
}

pub fn compute_base_score(metrics: &CvssMetrics) -> ScoreResult {
    let c = metrics.confidentiality.weight();
    let i = metrics.integrity.weight();
    let a = metrics.availability.weight();

    // Impact Sub Score
    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));

    // Impact
    let impact = match metrics.scope {
        Scope::Unchanged => 6.42 * iss,
        Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0),
    };

    if impact <= 0.0 {
        return ScoreResult {
            score: 0.0,
            severity: "NONE".to_string(),
            iss,
            impact,
            exploitability: 0.0,
        };
    }

    // Exploitability
    let exploitability = 8.22
        * metrics.av.weight()
        * metrics.ac.weight()
        * metrics.pr.weight(metrics.scope)
        * metrics.ui.weight();

    let score = match metrics.scope {
        Scope::Unchanged => roundup((impact + exploitability).min(10.0)),
        Scope::Changed => roundup((1.08 * (impact + exploitability)).min(10.0)),
    };

    ScoreResult {
        score,
        severity: severity_from_score(score),
        iss,
        impact,
        exploitability,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cvss::metrics::*;
    use crate::cvss::vector::parse_vector;

    #[test]
    fn roundup_values() {
        assert_eq!(roundup(4.02), 4.1);
        assert_eq!(roundup(4.00), 4.0);
        assert_eq!(roundup(0.0), 0.0);
        assert_eq!(roundup(4.1), 4.1);
        assert_eq!(roundup(9.99), 10.0);
        assert_eq!(roundup(10.0), 10.0);
        assert_eq!(roundup(0.1), 0.1);
        assert_eq!(roundup(0.01), 0.1);
        assert_eq!(roundup(7.0), 7.0);
        assert_eq!(roundup(7.001), 7.1);
        assert_eq!(roundup(3.9), 3.9);
        assert_eq!(roundup(3.91), 4.0);
    }

    #[test]
    fn severity_ranges() {
        assert_eq!(severity_from_score(0.0), "NONE");
        assert_eq!(severity_from_score(0.1), "LOW");
        assert_eq!(severity_from_score(3.9), "LOW");
        assert_eq!(severity_from_score(4.0), "MEDIUM");
        assert_eq!(severity_from_score(6.9), "MEDIUM");
        assert_eq!(severity_from_score(7.0), "HIGH");
        assert_eq!(severity_from_score(8.9), "HIGH");
        assert_eq!(severity_from_score(9.0), "CRITICAL");
        assert_eq!(severity_from_score(10.0), "CRITICAL");
    }

    /// Known vectors verified against NIST CVSS v3.1 calculator.
    const KNOWN_VECTORS: &[(&str, f64, &str)] = &[
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "MEDIUM"),
        ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 4.6, "MEDIUM"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH"),
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "HIGH"),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "HIGH"),
        ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5, "HIGH"),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8, "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "NONE"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "MEDIUM"),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L", 3.5, "LOW"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "HIGH"),
    ];

    #[test]
    fn known_vectors_match_nist() {
        for (vector, expected_score, expected_severity) in KNOWN_VECTORS {
            let metrics = parse_vector(vector).unwrap();
            let result = compute_base_score(&metrics);
            assert_eq!(
                result.score, *expected_score,
                "score mismatch for {vector}: got {}, expected {expected_score}",
                result.score
            );
            assert_eq!(
                result.severity, *expected_severity,
                "severity mismatch for {vector}: got {}, expected {expected_severity}",
                result.severity
            );
        }
    }

    #[test]
    fn zero_impact_always_zero() {
        let metrics = CvssMetrics {
            av: AttackVector::Network,
            ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None,
            ui: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: CiaImpact::None,
            integrity: CiaImpact::None,
            availability: CiaImpact::None,
        };
        assert_eq!(compute_base_score(&metrics).score, 0.0);
    }

    #[test]
    fn scope_changed_affects_score() {
        let mut metrics = parse_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H").unwrap();
        let score_u = compute_base_score(&metrics).score;

        metrics.scope = Scope::Changed;
        // PR weight changes with scope, so re-parsing is more accurate,
        // but we want to show the direct effect
        let score_c = compute_base_score(&metrics).score;

        assert_ne!(score_u, score_c);
        assert_eq!(score_u, 7.8);
        assert_eq!(score_c, 8.8);
    }

    #[test]
    fn exhaustive_all_combinations_in_range() {
        // Test all 2592 metric combinations produce valid scores
        let avs = [AttackVector::Network, AttackVector::Adjacent, AttackVector::Local, AttackVector::Physical];
        let acs = [AttackComplexity::Low, AttackComplexity::High];
        let prs = [PrivilegesRequired::None, PrivilegesRequired::Low, PrivilegesRequired::High];
        let uis = [UserInteraction::None, UserInteraction::Required];
        let scopes = [Scope::Unchanged, Scope::Changed];
        let cias = [CiaImpact::High, CiaImpact::Low, CiaImpact::None];

        for av in &avs {
            for ac in &acs {
                for pr in &prs {
                    for ui in &uis {
                        for scope in &scopes {
                            for c in &cias {
                                for i in &cias {
                                    for a in &cias {
                                        let metrics = CvssMetrics {
                                            av: *av, ac: *ac, pr: *pr, ui: *ui,
                                            scope: *scope,
                                            confidentiality: *c, integrity: *i, availability: *a,
                                        };
                                        let result = compute_base_score(&metrics);
                                        assert!(
                                            (0.0..=10.0).contains(&result.score),
                                            "score {} out of range",
                                            result.score
                                        );
                                        // Severity must match score range
                                        match result.severity.as_str() {
                                            "NONE" => assert_eq!(result.score, 0.0),
                                            "LOW" => assert!((0.1..=3.9).contains(&result.score), "{}", result.score),
                                            "MEDIUM" => assert!((4.0..=6.9).contains(&result.score), "{}", result.score),
                                            "HIGH" => assert!((7.0..=8.9).contains(&result.score), "{}", result.score),
                                            "CRITICAL" => assert!((9.0..=10.0).contains(&result.score), "{}", result.score),
                                            s => panic!("unexpected severity: {s}"),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
