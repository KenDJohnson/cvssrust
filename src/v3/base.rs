//! CVSS v3 base metrics

use crate::common::cvss_metric;

use crate::common::{NumValue, ParseError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::str;

pub const METRICS: &[&str] = &["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum AttackVector "Attack Vector" "AV" {
        Network: 0 => "N",
        Adjacent: 1 => "A",
        Local: 2 => "L",
        Physical: 3 => "P",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum AttackComplexity "Attack Complexity" "AC" {
        Low: 0 => "L",
        High: 1 => "H",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum PrivilegesRequired "Privileges Required" "PR" {
        None: 0 => "N",
        Low: 1 => "L",
        High: 2 => "H",
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum UserInteraction "User Interaction" "UI" {
        None: 0 => "N",
        Required: 1 => "R",
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Confidentiality {
    High,
    Low,
    None,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Integrity {
    High,
    Low,
    None,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Availability {
    High,
    Low,
    None,
}

impl NumValue for AttackVector {
    fn num_value(&self) -> f64 {
        match self {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }
}

impl NumValue for AttackComplexity {
    fn num_value(&self) -> f64 {
        match self {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }
}

impl NumValue for PrivilegesRequired {
    fn num_value(&self) -> f64 {
        self.num_value_scoped(false)
    }

    fn num_value_scoped(&self, scope_change: bool) -> f64 {
        match self {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => {
                if scope_change {
                    0.68
                } else {
                    0.62
                }
            }
            PrivilegesRequired::High => {
                if scope_change {
                    0.5
                } else {
                    0.27
                }
            }
        }
    }
}

impl NumValue for UserInteraction {
    fn num_value(&self) -> f64 {
        match self {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }
}

impl AsRef<str> for Scope {
    fn as_ref(&self) -> &str {
        match self {
            Scope::Unchanged => "U",
            Scope::Changed => "C",
        }
    }
}

impl str::FromStr for Scope {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "U" => Ok(Scope::Unchanged),
            "C" => Ok(Scope::Changed),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl AsRef<str> for Confidentiality {
    fn as_ref(&self) -> &str {
        match self {
            Confidentiality::High => "H",
            Confidentiality::Low => "L",
            Confidentiality::None => "N",
        }
    }
}

impl str::FromStr for Confidentiality {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Confidentiality::High),
            "L" => Ok(Confidentiality::Low),
            "N" => Ok(Confidentiality::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Confidentiality {
    fn num_value(&self) -> f64 {
        match self {
            Confidentiality::High => 0.56,
            Confidentiality::Low => 0.22,
            Confidentiality::None => 0.0,
        }
    }
}

impl AsRef<str> for Integrity {
    fn as_ref(&self) -> &str {
        match self {
            Integrity::High => "H",
            Integrity::Low => "L",
            Integrity::None => "N",
        }
    }
}

impl str::FromStr for Integrity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Integrity::High),
            "L" => Ok(Integrity::Low),
            "N" => Ok(Integrity::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Integrity {
    fn num_value(&self) -> f64 {
        match self {
            Integrity::High => 0.56,
            Integrity::Low => 0.22,
            Integrity::None => 0.0,
        }
    }
}

impl AsRef<str> for Availability {
    fn as_ref(&self) -> &str {
        match self {
            Availability::High => "H",
            Availability::Low => "L",
            Availability::None => "N",
        }
    }
}

impl str::FromStr for Availability {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Availability::High),
            "L" => Ok(Availability::Low),
            "N" => Ok(Availability::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Availability {
    fn num_value(&self) -> f64 {
        match self {
            Availability::High => 0.56,
            Availability::Low => 0.22,
            Availability::None => 0.0,
        }
    }
}
