//! CVSS v2 environmental metrics

use crate::common::{optional_metric, NumValue, ParseError};
use std::str;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum CollateralDamagePotential {
    None,
    Low,
    LowMedium,
    MediumHigh,
    High,
    NotDefined,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum TargetDistribution {
    None,
    Low,
    Medium,
    High,
    NotDefined,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ConfidentialityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum IntegrityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum AvailabilityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

impl AsRef<str> for CollateralDamagePotential {
    fn as_ref(&self) -> &str {
        match self {
            CollateralDamagePotential::NotDefined => "ND",
            CollateralDamagePotential::None => "N",
            CollateralDamagePotential::Low => "L",
            CollateralDamagePotential::LowMedium => "LM",
            CollateralDamagePotential::MediumHigh => "MH",
            CollateralDamagePotential::High => "H",
        }
    }
}

impl str::FromStr for CollateralDamagePotential {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(CollateralDamagePotential::NotDefined),
            "N" => Ok(CollateralDamagePotential::None),
            "L" => Ok(CollateralDamagePotential::Low),
            "LM" => Ok(CollateralDamagePotential::LowMedium),
            "MH" => Ok(CollateralDamagePotential::MediumHigh),
            "H" => Ok(CollateralDamagePotential::High),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for CollateralDamagePotential {
    fn num_value(&self) -> f64 {
        match self {
            CollateralDamagePotential::NotDefined => 0.0,
            CollateralDamagePotential::None => 0.0,
            CollateralDamagePotential::Low => 0.1,
            CollateralDamagePotential::LowMedium => 0.3,
            CollateralDamagePotential::MediumHigh => 0.4,
            CollateralDamagePotential::High => 0.5,
        }
    }
}

optional_metric! { CollateralDamagePotential::NotDefined }

impl AsRef<str> for TargetDistribution {
    fn as_ref(&self) -> &str {
        match self {
            TargetDistribution::NotDefined => "ND",
            TargetDistribution::High => "H",
            TargetDistribution::Medium => "M",
            TargetDistribution::Low => "L",
            TargetDistribution::None => "N",
        }
    }
}

impl str::FromStr for TargetDistribution {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(TargetDistribution::NotDefined),
            "H" => Ok(TargetDistribution::High),
            "M" => Ok(TargetDistribution::Medium),
            "L" => Ok(TargetDistribution::Low),
            "N" => Ok(TargetDistribution::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for TargetDistribution {
    fn num_value(&self) -> f64 {
        match self {
            TargetDistribution::NotDefined => 1.0,
            TargetDistribution::High => 1.0,
            TargetDistribution::Medium => 0.75,
            TargetDistribution::Low => 0.25,
            TargetDistribution::None => 0.0,
        }
    }
}
optional_metric! { TargetDistribution::NotDefined }

impl AsRef<str> for ConfidentialityRequirement {
    fn as_ref(&self) -> &str {
        match self {
            ConfidentialityRequirement::NotDefined => "ND",
            ConfidentialityRequirement::High => "H",
            ConfidentialityRequirement::Medium => "M",
            ConfidentialityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for ConfidentialityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(ConfidentialityRequirement::NotDefined),
            "H" => Ok(ConfidentialityRequirement::High),
            "M" => Ok(ConfidentialityRequirement::Medium),
            "L" => Ok(ConfidentialityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ConfidentialityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            ConfidentialityRequirement::NotDefined => 1.0,
            ConfidentialityRequirement::High => 1.51,
            ConfidentialityRequirement::Medium => 1.0,
            ConfidentialityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { ConfidentialityRequirement::NotDefined }

impl AsRef<str> for IntegrityRequirement {
    fn as_ref(&self) -> &str {
        match self {
            IntegrityRequirement::NotDefined => "ND",
            IntegrityRequirement::High => "H",
            IntegrityRequirement::Medium => "M",
            IntegrityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for IntegrityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(IntegrityRequirement::NotDefined),
            "H" => Ok(IntegrityRequirement::High),
            "M" => Ok(IntegrityRequirement::Medium),
            "L" => Ok(IntegrityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for IntegrityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            IntegrityRequirement::NotDefined => 1.0,
            IntegrityRequirement::High => 1.51,
            IntegrityRequirement::Medium => 1.0,
            IntegrityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { IntegrityRequirement::NotDefined }

impl AsRef<str> for AvailabilityRequirement {
    fn as_ref(&self) -> &str {
        match self {
            AvailabilityRequirement::NotDefined => "ND",
            AvailabilityRequirement::High => "H",
            AvailabilityRequirement::Medium => "M",
            AvailabilityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for AvailabilityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ND" => Ok(AvailabilityRequirement::NotDefined),
            "H" => Ok(AvailabilityRequirement::High),
            "M" => Ok(AvailabilityRequirement::Medium),
            "L" => Ok(AvailabilityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AvailabilityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            AvailabilityRequirement::NotDefined => 1.0,
            AvailabilityRequirement::High => 1.51,
            AvailabilityRequirement::Medium => 1.0,
            AvailabilityRequirement::Low => 0.5,
        }
    }
}

optional_metric! { AvailabilityRequirement::NotDefined }
