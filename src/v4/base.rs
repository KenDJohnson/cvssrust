//! CVSS v4 base metrics
use crate::common::cvss_metric;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::v3::base::{AttackComplexity, AttackVector, PrivilegesRequired};

pub const METRICS: &[&str] = &[
    "AV", "AC", "AR", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

// Exploitability

#[macro_export]
macro_rules! AV {
    (N) => {
        $crate::v4::base::AttackVector::Network
    };
    (A) => {
        $crate::v4::base::AttackVector::Adjacent
    };
    (L) => {
        $crate::v4::base::AttackVector::Local
    };
    (P) => {
        $crate::v4::base::AttackVector::Physical
    };
}

#[macro_export]
macro_rules! AC {
    (L) => {
        $crate::v4::base::AttackComplexity::Low
    };
    (H) => {
        $crate::v4::base::AttackComplexity::High
    };
}

#[macro_export]
macro_rules! PR {
    (N) => {
        $crate::v4::base::PrivilegesRequired::None
    };
    (L) => {
        $crate::v4::base::PrivilegesRequired::Low
    };
    (H) => {
        $crate::v4::base::PrivilegesRequired::High
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum AttackRequirements "Attack Requirements" "AT" {
        None: 0 => "N",
        Present: 1 => "P",
    }
}

#[macro_export]
macro_rules! AT {
    (N) => {
        $crate::v4::base::AttackRequirements::None
    };
    (P) => {
        $crate::v4::base::AttackRequirements::Present
    };
}

impl Default for AttackRequirements {
    fn default() -> Self {
        Self::None
    }
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum UserInteraction "User Interaction" "UI" {
        None: 0 => "N",
        Passive: 1 => "P",
        Active: 2 => "A",
    }
}
#[macro_export]
macro_rules! UI {
    (N) => {
        $crate::v4::base::UserInteraction::None
    };
    (P) => {
        $crate::v4::base::UserInteraction::Passive
    };
    (A) => {
        $crate::v4::base::UserInteraction::Active
    };
}

impl Default for UserInteraction {
    fn default() -> Self {
        Self::None
    }
}

// Impact

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum VulnerableSystemConfidentiality "Vulnerable System Confidentiality Impact" "VC" {
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! VC {
    (H) => {
        $crate::v4::base::VulnerableSystemConfidentiality::High
    };
    (L) => {
        $crate::v4::base::VulnerableSystemConfidentiality::Low
    };
    (N) => {
        $crate::v4::base::VulnerableSystemConfidentiality::None
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum VulnerableSystemIntegrity "Vulnerable System Integrity Impact" "VI" {
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! VI {
    (H) => {
        $crate::v4::base::VulnerableSystemIntegrity::High
    };
    (L) => {
        $crate::v4::base::VulnerableSystemIntegrity::Low
    };
    (N) => {
        $crate::v4::base::VulnerableSystemIntegrity::None
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum VulnerableSystemAvailability "Vulnerable System Availability Impact" "VA" {
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! VA {
    (H) => {
        $crate::v4::base::VulnerableSystemAvailability::High
    };
    (L) => {
        $crate::v4::base::VulnerableSystemAvailability::Low
    };
    (N) => {
        $crate::v4::base::VulnerableSystemAvailability::None
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum SubsequentSystemConfidentiality "Subsequent System Confidentiality Impact" "SC" {
        High: 1 => "H",
        Low: 2 => "L",
        Negligible: 3 => "N",
    }
}

#[macro_export]
macro_rules! SC {
    (H) => {
        $crate::v4::base::SubsequentSystemConfidentiality::High
    };
    (L) => {
        $crate::v4::base::SubsequentSystemConfidentiality::Low
    };
    (N) => {
        $crate::v4::base::SubsequentSystemConfidentiality::None
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum SubsequentSystemIntegrity "Subsequent System Integrity Impact" "SI" {
        High: 1 => "H",
        Low: 2 => "L",
        None: 3 => "N",
    }
}

#[macro_export]
macro_rules! SI {
    (H) => {
        $crate::v4::base::SubsequentSystemIntegrity::High
    };
    (L) => {
        $crate::v4::base::SubsequentSystemIntegrity::Low
    };
    (N) => {
        $crate::v4::base::SubsequentSystemIntegrity::None
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    #[repr(u8)]
    pub enum SubsequentSystemAvailability "Subsequent System Availability Impact" "SA" {
        High: 1 => "H",
        Low: 2 => "L",
        None: 3 => "N",
    }
}
#[macro_export]
macro_rules! SA {
    (H) => {
        $crate::v4::base::SubsequentSystemAvailability::High
    };
    (L) => {
        $crate::v4::base::SubsequentSystemAvailability::Low
    };
    (N) => {
        $crate::v4::base::SubsequentSystemAvailability::None
    };
}
