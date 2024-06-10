use crate::common::{cvss_metric, optional_metric};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum Safety "Safety" "S" {
        NotDefined: 0 => "X",
        Present: 0 => "P",
        Negligible: 1 => "N",
    }
}

#[macro_export]
macro_rules! S {
    (X) => {
        $crate::v4::supplemental::Safety::NotDefined
    };
    (P) => {
        $crate::v4::supplemental::Safety::Present
    };
    (N) => {
        $crate::v4::supplemental::Safety::Negligible
    };
}

optional_metric! { Safety::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum Automatable "Automatable" "AU" {
        NotDefined: 0 => "X",
        No: 0 => "N",
        Yes: 1 => "Y",
    }
}

#[macro_export]
macro_rules! AU {
    (X) => {
        $crate::v4::supplemental::Automatable::NotDefined
    };
    (N) => {
        $crate::v4::supplemental::Automatable::No
    };
    (Y) => {
        $crate::v4::supplemental::Automatable::Yes
    };
}

optional_metric! { Automatable::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ProviderUrgency "Provider Urgency" "U" {
        NotDefined: 0 => "X",
        Red: 0 => "Red",
        Amber: 1 => "Amber",
        Green: 2 => "Green",
        Clear: 3 => "Clear",
    }
}

#[macro_export]
macro_rules! U {
    (X) => {
        $crate::v4::supplemental::ProviderUrgency::NotDefined
    };
    (Red) => {
        $crate::v4::supplemental::ProviderUrgency::Red
    };
    (Amber) => {
        $crate::v4::supplemental::ProviderUrgency::Amber
    };
    (Green) => {
        $crate::v4::supplemental::ProviderUrgency::Green
    };
    (Clear) => {
        $crate::v4::supplemental::ProviderUrgency::Clear
    };
}

optional_metric! { ProviderUrgency::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum Recovery "Recovery" "R" {
        NotDefined: 0 => "X",
        Automatic: 1 => "A",
        User: 2 => "U",
        Irrecoverable: 3 => "I",
    }
}

#[macro_export]
macro_rules! R {
    (X) => {
        $crate::v4::supplemental::Recovery::NotDefined
    };
    (A) => {
        $crate::v4::supplemental::Recovery::Automatic
    };
    (U) => {
        $crate::v4::supplemental::Recovery::User
    };
    (I) => {
        $crate::v4::supplemental::Recovery::Irrecoverable
    };
}

optional_metric! { Recovery::NotDefined }

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ValueDensity "Value Density" "V" {
        NotDefined: 0 => "X",
        Diffuse: 0 => "D",
        Concentrated: 1 => "C",
    }
}

optional_metric! { ValueDensity::NotDefined }

#[macro_export]
macro_rules! V {
    (X) => {
        $crate::v4::supplemental::ValueDensity::NotDefined
    };
    (C) => {
        $crate::v4::supplemental::ValueDensity::Diffuse
    };
    (C) => {
        $crate::v4::supplemental::ValueDensity::Concentrated
    };
}

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum VulnerabilityResponseEffort "Vulnerability Response Effort" "RE" {
        NotDefined: 0 => "X",
        Low: 0 => "L",
        Moderate: 1 => "M",
        High: 2 => "H",
    }
}

optional_metric! { VulnerabilityResponseEffort::NotDefined }

#[macro_export]
macro_rules! RE {
    (X) => {
        $crate::v4::supplemental::VulnerabilityResponseEffort::NotDefined
    };
    (L) => {
        $crate::v4::supplemental::VulnerabilityResponseEffort::Low
    };
    (M) => {
        $crate::v4::supplemental::VulnerabilityResponseEffort::Moderate
    };
    (H) => {
        $crate::v4::supplemental::VulnerabilityResponseEffort::High
    };
}
