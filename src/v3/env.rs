//! CVSS v3 environmental metrics

use crate::common::{cvss_metric, optional_metric, NumValue, ParseError};
use std::str;

pub const METRICS: &[&str] = &[
    "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
];

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ConfidentialityRequirement "Confidentiality Requirement" "CR" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Medium: 1 => "M",
        Low: 2 => "L",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum IntegrityRequirement "Integrity Requirement" "IR" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Medium: 1 => "M",
        Low: 2 => "L",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum AvailabilityRequirement "Availability Requirement" "AR" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Medium: 1 => "M",
        Low: 2 => "L",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedAttackVector "Modified Attack Vector" "MAV" {
        NotDefined: 0 => "X",
        Network: 0 => "N",
        Adjacent: 1 => "A",
        Local: 2 => "L",
        Physical: 3 => "P",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedAttackComplexity "Modified Attack Complexity" "MAC" {
        NotDefined: 0 => "X",
        Low: 0 => "L",
        High: 1 => "H",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedPrivilegesRequired "Modified Privileges Required" "MPR"{
        NotDefined: 0 => "X",
        None: 0 => "N",
        Low: 1 => "L",
        High: 2 => "H",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedUserInteraction "Modified User Interaction" "MUI" {
        NotDefined: 0 => "X",
        None: 0 => "N",
        Required: 1 => "R",
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedScope {
    NotDefined,
    Unchanged,
    Changed,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedConfidentiality {
    NotDefined,
    None,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedIntegrity {
    NotDefined,
    None,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedAvailability {
    NotDefined,
    None,
    Low,
    High,
}

impl NumValue for ConfidentialityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            ConfidentialityRequirement::NotDefined => 1.0,
            ConfidentialityRequirement::High => 1.5,
            ConfidentialityRequirement::Medium => 1.0,
            ConfidentialityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { ConfidentialityRequirement::NotDefined }

impl NumValue for IntegrityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            IntegrityRequirement::NotDefined => 1.0,
            IntegrityRequirement::High => 1.5,
            IntegrityRequirement::Medium => 1.0,
            IntegrityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { IntegrityRequirement::NotDefined }

impl NumValue for AvailabilityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            AvailabilityRequirement::NotDefined => 1.0,
            AvailabilityRequirement::High => 1.5,
            AvailabilityRequirement::Medium => 1.0,
            AvailabilityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { AvailabilityRequirement::NotDefined }

impl NumValue for ModifiedAttackVector {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAttackVector::NotDefined => 1.0,
            ModifiedAttackVector::Network => 0.85,
            ModifiedAttackVector::Adjacent => 0.62,
            ModifiedAttackVector::Local => 0.55,
            ModifiedAttackVector::Physical => 0.2,
        }
    }
}

optional_metric! { ModifiedAttackVector::NotDefined }

impl NumValue for ModifiedAttackComplexity {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAttackComplexity::NotDefined => 1.0,
            ModifiedAttackComplexity::Low => 0.77,
            ModifiedAttackComplexity::High => 0.44,
        }
    }
}

optional_metric! { ModifiedAttackComplexity::NotDefined }

impl NumValue for ModifiedPrivilegesRequired {
    fn num_value(&self) -> f64 {
        self.num_value_scoped(false)
    }

    fn num_value_scoped(&self, scope_change: bool) -> f64 {
        match self {
            ModifiedPrivilegesRequired::NotDefined => 1.0,
            ModifiedPrivilegesRequired::None => 0.85,
            ModifiedPrivilegesRequired::Low => {
                if scope_change {
                    0.68
                } else {
                    0.62
                }
            }
            ModifiedPrivilegesRequired::High => {
                if scope_change {
                    0.5
                } else {
                    0.27
                }
            }
        }
    }
}

optional_metric! { ModifiedPrivilegesRequired::NotDefined }

impl NumValue for ModifiedUserInteraction {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedUserInteraction::NotDefined => 1.0,
            ModifiedUserInteraction::None => 0.85,
            ModifiedUserInteraction::Required => 0.62,
        }
    }
}

optional_metric! { ModifiedUserInteraction::NotDefined }

impl AsRef<str> for ModifiedScope {
    fn as_ref(&self) -> &str {
        match self {
            ModifiedScope::NotDefined => "X",
            ModifiedScope::Unchanged => "U",
            ModifiedScope::Changed => "C",
        }
    }
}

impl str::FromStr for ModifiedScope {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedScope::NotDefined),
            "U" => Ok(ModifiedScope::Unchanged),
            "C" => Ok(ModifiedScope::Changed),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

optional_metric! { ModifiedScope::NotDefined }

impl AsRef<str> for ModifiedConfidentiality {
    fn as_ref(&self) -> &str {
        match self {
            ModifiedConfidentiality::NotDefined => "X",
            ModifiedConfidentiality::High => "H",
            ModifiedConfidentiality::Low => "L",
            ModifiedConfidentiality::None => "N",
        }
    }
}

impl str::FromStr for ModifiedConfidentiality {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedConfidentiality::NotDefined),
            "H" => Ok(ModifiedConfidentiality::High),
            "L" => Ok(ModifiedConfidentiality::Low),
            "N" => Ok(ModifiedConfidentiality::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ModifiedConfidentiality {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedConfidentiality::NotDefined => 1.0,
            ModifiedConfidentiality::High => 0.56,
            ModifiedConfidentiality::Low => 0.22,
            ModifiedConfidentiality::None => 0.0,
        }
    }
}

optional_metric! { ModifiedConfidentiality::NotDefined }

impl AsRef<str> for ModifiedIntegrity {
    fn as_ref(&self) -> &str {
        match self {
            ModifiedIntegrity::NotDefined => "X",
            ModifiedIntegrity::High => "H",
            ModifiedIntegrity::Low => "L",
            ModifiedIntegrity::None => "N",
        }
    }
}

impl str::FromStr for ModifiedIntegrity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedIntegrity::NotDefined),
            "H" => Ok(ModifiedIntegrity::High),
            "L" => Ok(ModifiedIntegrity::Low),
            "N" => Ok(ModifiedIntegrity::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ModifiedIntegrity {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedIntegrity::NotDefined => 1.0,
            ModifiedIntegrity::High => 0.56,
            ModifiedIntegrity::Low => 0.22,
            ModifiedIntegrity::None => 0.0,
        }
    }
}

optional_metric! { ModifiedIntegrity::NotDefined }

impl AsRef<str> for ModifiedAvailability {
    fn as_ref(&self) -> &str {
        match self {
            ModifiedAvailability::NotDefined => "X",
            ModifiedAvailability::High => "H",
            ModifiedAvailability::Low => "L",
            ModifiedAvailability::None => "N",
        }
    }
}

impl str::FromStr for ModifiedAvailability {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedAvailability::NotDefined),
            "H" => Ok(ModifiedAvailability::High),
            "L" => Ok(ModifiedAvailability::Low),
            "N" => Ok(ModifiedAvailability::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ModifiedAvailability {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAvailability::NotDefined => 1.0,
            ModifiedAvailability::High => 0.56,
            ModifiedAvailability::Low => 0.22,
            ModifiedAvailability::None => 0.0,
        }
    }
}

optional_metric! { ModifiedAvailability::NotDefined }
