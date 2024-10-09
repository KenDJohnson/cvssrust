use crate::common::{cvss_metric, optional_metric};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const METRICS: &[&str] = &["E"];

cvss_metric! {
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub enum ExploitMaturity "Exploit Maturity" "E" {
        NotDefined: 0 => "X",
        Attacked: 0 => "A",
        ProofOfConcept: 1 => "P",
        Unreported: 2 => "U",
    }
}
optional_metric! { ExploitMaturity::NotDefined }

#[macro_export]
macro_rules! E {
    (X) => {
        $crate::v4::threat::ExploitMaturity::NotDefined
    };
    (A) => {
        $crate::v4::threat::ExploitMaturity::Attacked
    };
    (P) => {
        $crate::v4::threat::ExploitMaturity::ProofOfConcept
    };
    (U) => {
        $crate::v4::threat::ExploitMaturity::Unreported
    };
}
