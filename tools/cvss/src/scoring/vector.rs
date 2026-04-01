// SPDX-License-Identifier: GPL-2.0-only
//
// CVSS v3.1 vector string parsing and formatting.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Result};

use super::metrics::*;

const VECTOR_PREFIX: &str = "CVSS:3.1/";
const METRIC_COUNT: usize = 8;

/// Parse a CVSS v3.1 vector string into CvssMetrics.
///
/// Expected format: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
pub fn parse_vector(s: &str) -> Result<CvssMetrics> {
    let s = s.trim();

    if s.is_empty() {
        return Err(anyhow!("empty vector string"));
    }

    let rest = s
        .strip_prefix(VECTOR_PREFIX)
        .ok_or_else(|| anyhow!("vector must start with '{VECTOR_PREFIX}', got: '{s}'"))?;

    let parts: Vec<&str> = rest.split('/').collect();

    if parts.len() < METRIC_COUNT {
        return Err(anyhow!(
            "expected {METRIC_COUNT} metrics, got {}: '{s}'",
            parts.len()
        ));
    }

    if parts.len() > METRIC_COUNT {
        return Err(anyhow!(
            "expected {METRIC_COUNT} metrics, got {} (extra fields): '{s}'",
            parts.len()
        ));
    }

    let mut av = None;
    let mut ac = None;
    let mut pr = None;
    let mut ui = None;
    let mut scope = None;
    let mut confidentiality = None;
    let mut integrity = None;
    let mut availability = None;

    for part in &parts {
        let (key, value) = part
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid metric format: '{part}'"))?;

        match key {
            "AV" => {
                if av.is_some() {
                    return Err(anyhow!("duplicate metric: AV"));
                }
                av = Some(AttackVector::from_abbreviation(value)?);
            }
            "AC" => {
                if ac.is_some() {
                    return Err(anyhow!("duplicate metric: AC"));
                }
                ac = Some(AttackComplexity::from_abbreviation(value)?);
            }
            "PR" => {
                if pr.is_some() {
                    return Err(anyhow!("duplicate metric: PR"));
                }
                pr = Some(PrivilegesRequired::from_abbreviation(value)?);
            }
            "UI" => {
                if ui.is_some() {
                    return Err(anyhow!("duplicate metric: UI"));
                }
                ui = Some(UserInteraction::from_abbreviation(value)?);
            }
            "S" => {
                if scope.is_some() {
                    return Err(anyhow!("duplicate metric: S"));
                }
                scope = Some(Scope::from_abbreviation(value)?);
            }
            "C" => {
                if confidentiality.is_some() {
                    return Err(anyhow!("duplicate metric: C"));
                }
                confidentiality = Some(CiaImpact::from_abbreviation(value)?);
            }
            "I" => {
                if integrity.is_some() {
                    return Err(anyhow!("duplicate metric: I"));
                }
                integrity = Some(CiaImpact::from_abbreviation(value)?);
            }
            "A" => {
                if availability.is_some() {
                    return Err(anyhow!("duplicate metric: A"));
                }
                availability = Some(CiaImpact::from_abbreviation(value)?);
            }
            _ => return Err(anyhow!("unknown metric: '{key}'")),
        }
    }

    Ok(CvssMetrics {
        av: av.ok_or_else(|| anyhow!("missing metric: AV"))?,
        ac: ac.ok_or_else(|| anyhow!("missing metric: AC"))?,
        pr: pr.ok_or_else(|| anyhow!("missing metric: PR"))?,
        ui: ui.ok_or_else(|| anyhow!("missing metric: UI"))?,
        scope: scope.ok_or_else(|| anyhow!("missing metric: S"))?,
        confidentiality: confidentiality.ok_or_else(|| anyhow!("missing metric: C"))?,
        integrity: integrity.ok_or_else(|| anyhow!("missing metric: I"))?,
        availability: availability.ok_or_else(|| anyhow!("missing metric: A"))?,
    })
}

/// Format CvssMetrics as a CVSS v3.1 vector string.
pub fn format_vector(metrics: &CvssMetrics) -> String {
    format!(
        "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
        metrics.av.abbreviation(),
        metrics.ac.abbreviation(),
        metrics.pr.abbreviation(),
        metrics.ui.abbreviation(),
        metrics.scope.abbreviation(),
        metrics.confidentiality.abbreviation(),
        metrics.integrity.abbreviation(),
        metrics.availability.abbreviation(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_vector() {
        let m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(m.av, AttackVector::Network);
        assert_eq!(m.ac, AttackComplexity::Low);
        assert_eq!(m.pr, PrivilegesRequired::None);
        assert_eq!(m.ui, UserInteraction::None);
        assert_eq!(m.scope, Scope::Unchanged);
        assert_eq!(m.confidentiality, CiaImpact::High);
        assert_eq!(m.integrity, CiaImpact::High);
        assert_eq!(m.availability, CiaImpact::High);
    }

    #[test]
    fn parse_all_physical_high() {
        let m = parse_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L").unwrap();
        assert_eq!(m.av, AttackVector::Physical);
        assert_eq!(m.ac, AttackComplexity::High);
        assert_eq!(m.pr, PrivilegesRequired::High);
        assert_eq!(m.ui, UserInteraction::Required);
        assert_eq!(m.scope, Scope::Changed);
        assert_eq!(m.confidentiality, CiaImpact::Low);
        assert_eq!(m.integrity, CiaImpact::Low);
        assert_eq!(m.availability, CiaImpact::Low);
    }

    #[test]
    fn format_roundtrip() {
        let vectors = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L",
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
            "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ];

        for v in vectors {
            let metrics = parse_vector(v).unwrap();
            assert_eq!(format_vector(&metrics), v, "roundtrip failed for {v}");
        }
    }

    #[test]
    fn parse_wrong_version() {
        assert!(parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
        assert!(parse_vector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn parse_invalid_value() {
        assert!(parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn parse_missing_metrics() {
        assert!(parse_vector("CVSS:3.1/AV:N/AC:L").is_err());
        assert!(parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").is_err());
    }

    #[test]
    fn parse_empty() {
        assert!(parse_vector("").is_err());
    }

    #[test]
    fn parse_garbage() {
        assert!(parse_vector("not a vector").is_err());
    }

    #[test]
    fn parse_extra_metrics() {
        assert!(
            parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/X:Y").is_err()
        );
    }

    #[test]
    fn parse_duplicate_metric() {
        assert!(
            parse_vector("CVSS:3.1/AV:N/AV:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err()
        );
    }

    #[test]
    fn parse_whitespace_trimmed() {
        let m =
            parse_vector("  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ").unwrap();
        assert_eq!(m.av, AttackVector::Network);
    }
}
