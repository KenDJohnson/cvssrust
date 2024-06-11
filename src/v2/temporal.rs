//! CVSS v2 temporal metrics

use crate::common::{optional_metric, NumValue, ParseError};
use std::str;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Exploitability {
    NotDefined,
    High,
    Functional,
    ProofOfConcept,
    Unproven,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ReportConfidence {
    Unconfirmed,
    Uncorroborated,
    Confirmed,
    NotDefined,
}

impl AsRef<str> for Exploitability {
    fn as_ref(&self) -> &str {
        match self {
            Exploitability::NotDefined => "ND",
            Exploitability::High => "H",
            Exploitability::Functional => "F",
            Exploitability::ProofOfConcept => "POC",
            Exploitability::Unproven => "U",
        }
    }
}

impl str::FromStr for Exploitability {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(Exploitability::NotDefined),
            "H" => Ok(Exploitability::High),
            "F" => Ok(Exploitability::Functional),
            "POC" => Ok(Exploitability::ProofOfConcept),
            "U" => Ok(Exploitability::Unproven),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Exploitability {
    fn num_value(&self) -> f64 {
        match self {
            Exploitability::NotDefined => 1.0,
            Exploitability::High => 1.0,
            Exploitability::Functional => 0.95,
            Exploitability::ProofOfConcept => 0.9,
            Exploitability::Unproven => 0.85,
        }
    }
}

optional_metric! { Exploitability::NotDefined }

impl AsRef<str> for RemediationLevel {
    fn as_ref(&self) -> &str {
        match self {
            RemediationLevel::NotDefined => "ND",
            RemediationLevel::Unavailable => "U",
            RemediationLevel::Workaround => "W",
            RemediationLevel::TemporaryFix => "TF",
            RemediationLevel::OfficialFix => "OF",
        }
    }
}

impl str::FromStr for RemediationLevel {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(RemediationLevel::NotDefined),
            "U" => Ok(RemediationLevel::Unavailable),
            "W" => Ok(RemediationLevel::Workaround),
            "TF" => Ok(RemediationLevel::TemporaryFix),
            "OF" => Ok(RemediationLevel::OfficialFix),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for RemediationLevel {
    fn num_value(&self) -> f64 {
        match self {
            RemediationLevel::NotDefined => 1.0,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::Workaround => 0.95,
            RemediationLevel::TemporaryFix => 0.90,
            RemediationLevel::OfficialFix => 0.87,
        }
    }
}

optional_metric! { RemediationLevel::NotDefined }

impl AsRef<str> for ReportConfidence {
    fn as_ref(&self) -> &str {
        match self {
            ReportConfidence::Unconfirmed => "UC",
            ReportConfidence::Uncorroborated => "UR",
            ReportConfidence::Confirmed => "C",
            ReportConfidence::NotDefined => "ND",
        }
    }
}

impl str::FromStr for ReportConfidence {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "UC" => Ok(ReportConfidence::Unconfirmed),
            "UR" => Ok(ReportConfidence::Uncorroborated),
            "C" => Ok(ReportConfidence::Confirmed),
            "ND" => Ok(ReportConfidence::NotDefined),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ReportConfidence {
    fn num_value(&self) -> f64 {
        match self {
            ReportConfidence::Unconfirmed => 0.90,
            ReportConfidence::Uncorroborated => 0.95,
            ReportConfidence::Confirmed => 1.0,
            ReportConfidence::NotDefined => 1.0,
        }
    }
}

optional_metric! { ReportConfidence::NotDefined }
