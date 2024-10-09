use crate::common::{cvss_metric, optional_metric};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use crate::v3::env::{
    AvailabilityRequirement, ConfidentialityRequirement, IntegrityRequirement,
    ModifiedAttackComplexity, ModifiedAttackVector, ModifiedPrivilegesRequired,
};

pub const METRICS: &[&str] = &[
    "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
];

#[macro_export]
macro_rules! CR {
    (X) => {
        $crate::v4::env::ConfidentialityRequirement::NotDefined
    };
    (H) => {
        $crate::v4::env::ConfidentialityRequirement::High
    };
    (M) => {
        $crate::v4::env::ConfidentialityRequirement::Medium
    };
    (L) => {
        $crate::v4::env::ConfidentialityRequirement::Low
    };
}

#[macro_export]
macro_rules! IR {
    (X) => {
        $crate::v4::env::IntegrityRequirement::NotDefined
    };
    (H) => {
        $crate::v4::env::IntegrityRequirement::High
    };
    (M) => {
        $crate::v4::env::IntegrityRequirement::Medium
    };
    (L) => {
        $crate::v4::env::IntegrityRequirement::Low
    };
}

#[macro_export]
macro_rules! AR {
    (X) => {
        $crate::v4::env::AvailabilityRequirement::NotDefined
    };
    (H) => {
        $crate::v4::env::AvailabilityRequirement::High
    };
    (M) => {
        $crate::v4::env::AvailabilityRequirement::Medium
    };
    (L) => {
        $crate::v4::env::AvailabilityRequirement::Low
    };
}

#[macro_export]
macro_rules! MAV {
    (X) => {
        $crate::v4::env::ModifiedAttackVector::NotDefined
    };
    (N) => {
        $crate::v4::env::ModifiedAttackVector::Network
    };
    (A) => {
        $crate::v4::env::ModifiedAttackVector::Adjacent
    };
    (L) => {
        $crate::v4::env::ModifiedAttackVector::Local
    };
    (P) => {
        $crate::v4::env::ModifiedAttackVector::Physical
    };
}

#[macro_export]
macro_rules! MAC {
    (X) => {
        $crate::v4::env::ModifiedAttackComplexity::NotDefined
    };
    (L) => {
        $crate::v4::env::ModifiedAttackComplexity::Low
    };
    (H) => {
        $crate::v4::env::ModifiedAttackComplexity::High
    };
}

#[macro_export]
macro_rules! MPR {
    (X) => {
        $crate::v4::env::ModifiedPrivilegesRequired::NotDefined
    };
    (N) => {
        $crate::v4::env::ModifiedPrivilegesRequired::None
    };
    (L) => {
        $crate::v4::env::ModifiedPrivilegesRequired::Low
    };
    (H) => {
        $crate::v4::env::ModifiedPrivilegesRequired::High
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedUserInteraction "Modified User Interaction" "MUI" {
        NotDefined: 0 => "X",
        None: 0 => "N",
        Passive: 1 => "P",
        Active: 2 => "A",
    }
}

optional_metric! { ModifiedUserInteraction::NotDefined }

#[macro_export]
macro_rules! MUI {
    (X) => {
        $crate::v4::env::ModifiedUserInteraction::NotDefined
    };
    (N) => {
        $crate::v4::env::ModifiedUserInteraction::None
    };
    (P) => {
        $crate::v4::env::ModifiedUserInteraction::Passive
    };
    (A) => {
        $crate::v4::env::ModifiedUserInteraction::Active
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedVulnerableSystemConfidentiality "Modified Vulnerable System Confidentiality Impact" "MVC" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! MVC {
    (X) => {
        $crate::v4::env::ModifiedVulnerableSystemConfidentiality::NotDefined
    };
    (H) => {
        $crate::v4::env::ModifiedVulnerableSystemConfidentiality::High
    };
    (L) => {
        $crate::v4::env::ModifiedVulnerableSystemConfidentiality::Low
    };
    (N) => {
        $crate::v4::env::ModifiedVulnerableSystemConfidentiality::None
    };
}

optional_metric! { ModifiedVulnerableSystemConfidentiality::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedVulnerableSystemIntegrity "Modified Vulnerable System Integrity Impact" "MVI" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! MVI {
    (X) => {
        $crate::v4::env::ModifiedVulnerableSystemIntegrity::NotDefined
    };
    (H) => {
        $crate::v4::env::ModifiedVulnerableSystemIntegrity::High
    };
    (L) => {
        $crate::v4::env::ModifiedVulnerableSystemIntegrity::Low
    };
    (N) => {
        $crate::v4::env::ModifiedVulnerableSystemIntegrity::None
    };
}

optional_metric! { ModifiedVulnerableSystemIntegrity::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedVulnerableSystemAvailability "Modified Vulnerable System Availability Impact" "MVA" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Low: 1 => "L",
        None: 2 => "N",
    }
}

#[macro_export]
macro_rules! MVA {
    (X) => {
        $crate::v4::env::ModifiedVulnerableSystemAvailability::NotDefined
    };
    (H) => {
        $crate::v4::env::ModifiedVulnerableSystemAvailability::High
    };
    (L) => {
        $crate::v4::env::ModifiedVulnerableSystemAvailability::Low
    };
    (N) => {
        $crate::v4::env::ModifiedVulnerableSystemAvailability::None
    };
}

optional_metric! { ModifiedVulnerableSystemAvailability::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedSubsequentSystemConfidentiality "Modified Subsequent System Confidentiality Impact" "MSC" {
        NotDefined: 0 => "X",
        High: 0 => "H",
        Low: 1 => "L",
        Negligible: 2 => "N",
    }
}

#[macro_export]
macro_rules! MSC {
    (X) => {
        $crate::v4::env::ModifiedSubsequentSystemConfidentiality::NotDefined
    };
    (H) => {
        $crate::v4::env::ModifiedSubsequentSystemConfidentiality::High
    };
    (L) => {
        $crate::v4::env::ModifiedSubsequentSystemConfidentiality::Low
    };
    (N) => {
        $crate::v4::env::ModifiedSubsequentSystemConfidentiality::Negligible
    };
}

optional_metric! { ModifiedSubsequentSystemConfidentiality::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedSubsequentSystemIntegrity "Modified Subsequent System Integrity Impact" "MSI" {
        NotDefined: 1 => "X",
        Safety: 0 => "S",
        High: 1 => "H",
        Low: 2 => "L",
        None: 3 => "N",
    }
}

#[macro_export]
macro_rules! MSI {
    (X) => {
        $crate::v4::env::ModifiedSubsequentSystemIntegrity::NotDefined
    };
    (S) => {
        $crate::v4::env::ModifiedSubsequentSystemIntegrity::Safety
    };
    (H) => {
        $crate::v4::env::ModifiedSubsequentSystemIntegrity::High
    };
    (L) => {
        $crate::v4::env::ModifiedSubsequentSystemIntegrity::Low
    };
    (N) => {
        $crate::v4::env::ModifiedSubsequentSystemIntegrity::None
    };
}

optional_metric! { ModifiedSubsequentSystemIntegrity::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ModifiedSubsequentSystemAvailability "Modified Subsequent System Availability Impact" "MSA" {
        NotDefined: 1 => "X",
        Safety: 0 => "S",
        High: 1 => "H",
        Low: 2 => "L",
        None: 3 => "N",
    }
}

optional_metric! { ModifiedSubsequentSystemAvailability::NotDefined }

#[macro_export]
macro_rules! MSA {
    (X) => {
        $crate::v4::env::ModifiedSubsequentSystemAvailability::NotDefined
    };
    (S) => {
        $crate::v4::env::ModifiedSubsequentSystemAvailability::Safety
    };
    (H) => {
        $crate::v4::env::ModifiedSubsequentSystemAvailability::High
    };
    (L) => {
        $crate::v4::env::ModifiedSubsequentSystemAvailability::Low
    };
    (N) => {
        $crate::v4::env::ModifiedSubsequentSystemAvailability::None
    };
}
