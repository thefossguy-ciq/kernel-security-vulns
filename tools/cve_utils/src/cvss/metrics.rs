// SPDX-License-Identifier: GPL-2.0-only
//
// CVSS v3.1 metric enums and constants per FIRST.org specification.
//
// Copyright (c) 2026 - Sasha Levin <sashal@kernel.org>

use anyhow::{anyhow, Result};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

impl AttackVector {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Network => 0.85,
            Self::Adjacent => 0.62,
            Self::Local => 0.55,
            Self::Physical => 0.20,
        }
    }

    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::Network => "N",
            Self::Adjacent => "A",
            Self::Local => "L",
            Self::Physical => "P",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "N" => Ok(Self::Network),
            "A" => Ok(Self::Adjacent),
            "L" => Ok(Self::Local),
            "P" => Ok(Self::Physical),
            _ => Err(anyhow!("invalid Attack Vector value: '{s}'")),
        }
    }
}

impl fmt::Display for AttackVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => write!(f, "Network"),
            Self::Adjacent => write!(f, "Adjacent"),
            Self::Local => write!(f, "Local"),
            Self::Physical => write!(f, "Physical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackComplexity {
    Low,
    High,
}

impl AttackComplexity {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.77,
            Self::High => 0.44,
        }
    }

    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::Low => "L",
            Self::High => "H",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "L" => Ok(Self::Low),
            "H" => Ok(Self::High),
            _ => Err(anyhow!("invalid Attack Complexity value: '{s}'")),
        }
    }
}

impl fmt::Display for AttackComplexity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

impl PrivilegesRequired {
    pub fn weight(&self, scope: Scope) -> f64 {
        match (self, scope) {
            (Self::None, _) => 0.85,
            (Self::Low, Scope::Unchanged) => 0.62,
            (Self::Low, Scope::Changed) => 0.68,
            (Self::High, Scope::Unchanged) => 0.27,
            (Self::High, Scope::Changed) => 0.50,
        }
    }

    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Low => "L",
            Self::High => "H",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "N" => Ok(Self::None),
            "L" => Ok(Self::Low),
            "H" => Ok(Self::High),
            _ => Err(anyhow!("invalid Privileges Required value: '{s}'")),
        }
    }
}

impl fmt::Display for PrivilegesRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInteraction {
    None,
    Required,
}

impl UserInteraction {
    pub fn weight(&self) -> f64 {
        match self {
            Self::None => 0.85,
            Self::Required => 0.62,
        }
    }

    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Required => "R",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "N" => Ok(Self::None),
            "R" => Ok(Self::Required),
            _ => Err(anyhow!("invalid User Interaction value: '{s}'")),
        }
    }
}

impl fmt::Display for UserInteraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Required => write!(f, "Required"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Unchanged,
    Changed,
}

impl Scope {
    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::Unchanged => "U",
            Self::Changed => "C",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "U" => Ok(Self::Unchanged),
            "C" => Ok(Self::Changed),
            _ => Err(anyhow!("invalid Scope value: '{s}'")),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => write!(f, "Unchanged"),
            Self::Changed => write!(f, "Changed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiaImpact {
    High,
    Low,
    None,
}

impl CiaImpact {
    pub fn weight(&self) -> f64 {
        match self {
            Self::High => 0.56,
            Self::Low => 0.22,
            Self::None => 0.0,
        }
    }

    pub fn abbreviation(&self) -> &'static str {
        match self {
            Self::High => "H",
            Self::Low => "L",
            Self::None => "N",
        }
    }

    pub fn from_abbreviation(s: &str) -> Result<Self> {
        match s {
            "H" => Ok(Self::High),
            "L" => Ok(Self::Low),
            "N" => Ok(Self::None),
            _ => Err(anyhow!("invalid CIA Impact value: '{s}'")),
        }
    }
}

impl fmt::Display for CiaImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "High"),
            Self::Low => write!(f, "Low"),
            Self::None => write!(f, "None"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CvssMetrics {
    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub scope: Scope,
    pub confidentiality: CiaImpact,
    pub integrity: CiaImpact,
    pub availability: CiaImpact,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_vector_weights() {
        assert_eq!(AttackVector::Network.weight(), 0.85);
        assert_eq!(AttackVector::Adjacent.weight(), 0.62);
        assert_eq!(AttackVector::Local.weight(), 0.55);
        assert_eq!(AttackVector::Physical.weight(), 0.20);
    }

    #[test]
    fn attack_complexity_weights() {
        assert_eq!(AttackComplexity::Low.weight(), 0.77);
        assert_eq!(AttackComplexity::High.weight(), 0.44);
    }

    #[test]
    fn privileges_required_weights_scope_unchanged() {
        assert_eq!(PrivilegesRequired::None.weight(Scope::Unchanged), 0.85);
        assert_eq!(PrivilegesRequired::Low.weight(Scope::Unchanged), 0.62);
        assert_eq!(PrivilegesRequired::High.weight(Scope::Unchanged), 0.27);
    }

    #[test]
    fn privileges_required_weights_scope_changed() {
        assert_eq!(PrivilegesRequired::None.weight(Scope::Changed), 0.85);
        assert_eq!(PrivilegesRequired::Low.weight(Scope::Changed), 0.68);
        assert_eq!(PrivilegesRequired::High.weight(Scope::Changed), 0.50);
    }

    #[test]
    fn user_interaction_weights() {
        assert_eq!(UserInteraction::None.weight(), 0.85);
        assert_eq!(UserInteraction::Required.weight(), 0.62);
    }

    #[test]
    fn cia_impact_weights() {
        assert_eq!(CiaImpact::High.weight(), 0.56);
        assert_eq!(CiaImpact::Low.weight(), 0.22);
        assert_eq!(CiaImpact::None.weight(), 0.0);
    }

    #[test]
    fn abbreviation_roundtrip() {
        for av in [
            AttackVector::Network,
            AttackVector::Adjacent,
            AttackVector::Local,
            AttackVector::Physical,
        ] {
            assert_eq!(AttackVector::from_abbreviation(av.abbreviation()).unwrap(), av);
        }

        for ac in [AttackComplexity::Low, AttackComplexity::High] {
            assert_eq!(
                AttackComplexity::from_abbreviation(ac.abbreviation()).unwrap(),
                ac
            );
        }

        for pr in [
            PrivilegesRequired::None,
            PrivilegesRequired::Low,
            PrivilegesRequired::High,
        ] {
            assert_eq!(
                PrivilegesRequired::from_abbreviation(pr.abbreviation()).unwrap(),
                pr
            );
        }

        for ui in [UserInteraction::None, UserInteraction::Required] {
            assert_eq!(
                UserInteraction::from_abbreviation(ui.abbreviation()).unwrap(),
                ui
            );
        }

        for s in [Scope::Unchanged, Scope::Changed] {
            assert_eq!(Scope::from_abbreviation(s.abbreviation()).unwrap(), s);
        }

        for cia in [CiaImpact::High, CiaImpact::Low, CiaImpact::None] {
            assert_eq!(
                CiaImpact::from_abbreviation(cia.abbreviation()).unwrap(),
                cia
            );
        }
    }

    #[test]
    fn invalid_abbreviations() {
        assert!(AttackVector::from_abbreviation("X").is_err());
        assert!(AttackComplexity::from_abbreviation("X").is_err());
        assert!(PrivilegesRequired::from_abbreviation("X").is_err());
        assert!(UserInteraction::from_abbreviation("X").is_err());
        assert!(Scope::from_abbreviation("X").is_err());
        assert!(CiaImpact::from_abbreviation("X").is_err());
    }
}
