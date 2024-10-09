//! CVSS v4 implementaion

use std::{fmt, iter::Peekable, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    common::{self, CvssMetric, Optional},
    ParseError, Score,
};

#[macro_use]
pub mod base;
#[macro_use]
pub mod env;
pub use env as environmental;
#[macro_use]
pub mod supplemental;
#[macro_use]
pub mod threat;
pub mod score;

use base::{
    AttackComplexity, AttackRequirements, AttackVector, PrivilegesRequired,
    SubsequentSystemAvailability, SubsequentSystemConfidentiality, SubsequentSystemIntegrity,
    UserInteraction, VulnerableSystemAvailability, VulnerableSystemConfidentiality,
    VulnerableSystemIntegrity,
};
use env::{
    AvailabilityRequirement, ConfidentialityRequirement, IntegrityRequirement,
    ModifiedAttackComplexity, ModifiedAttackVector, ModifiedPrivilegesRequired,
    ModifiedSubsequentSystemAvailability, ModifiedSubsequentSystemConfidentiality,
    ModifiedSubsequentSystemIntegrity, ModifiedUserInteraction,
    ModifiedVulnerableSystemAvailability, ModifiedVulnerableSystemConfidentiality,
    ModifiedVulnerableSystemIntegrity,
};
use supplemental::{
    Automatable, ProviderUrgency, Recovery, Safety, ValueDensity, VulnerabilityResponseEffort,
};
use threat::ExploitMaturity;

use self::score::Equations;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
/// CVSS vector version 4.0
///
/// ```
/// use cvssrust::v4::V4Vector;
/// use cvssrust::CVSSScore;
/// use std::str::FromStr;
///
/// let cvss_str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";
/// let cvss = V4Vector::from_str(cvss_str).unwrap();
///
/// assert_eq!(cvss.to_string(), String::from(cvss_str));
/// assert_eq!(cvss.base_score().value(), 6.1);
/// assert_eq!(cvss.base_score().severity().to_string(), "Medium");
/// assert_eq!(cvss.temporal_score().value(), 5.6);
///
/// let cvss_str = "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H";
/// let cvss: V4Vector = cvss_str.parse().unwrap();
/// ```
pub struct V4Vector {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub attack_requirements: AttackRequirements,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub vulnerable_confidentiality: VulnerableSystemConfidentiality,
    pub vulnerable_integrity: VulnerableSystemIntegrity,
    pub vulnerable_availability: VulnerableSystemAvailability,
    pub subsequent_confidentiality: SubsequentSystemConfidentiality,
    pub subsequent_integrity: SubsequentSystemIntegrity,
    pub subsequent_availability: SubsequentSystemAvailability,

    pub exploit_maturity: ExploitMaturity,

    pub confidentiality_requirement: ConfidentialityRequirement,
    pub integrity_requirement: IntegrityRequirement,
    pub availability_requirement: AvailabilityRequirement,
    pub modified_attack_vector: ModifiedAttackVector,
    pub modified_attack_complexity: ModifiedAttackComplexity,
    pub modified_privileges_required: ModifiedPrivilegesRequired,
    pub modified_user_interaction: ModifiedUserInteraction,
    pub modified_vulnerable_confidentiality: ModifiedVulnerableSystemConfidentiality,
    pub modified_vulnerable_integrity: ModifiedVulnerableSystemIntegrity,
    pub modified_vulnerable_availability: ModifiedVulnerableSystemAvailability,
    pub modified_subsequent_confidentiality: ModifiedSubsequentSystemConfidentiality,
    pub modified_subsequent_integrity: ModifiedSubsequentSystemIntegrity,
    pub modified_subsequent_availability: ModifiedSubsequentSystemAvailability,

    pub safety: Safety,
    pub automatable: Automatable,
    pub recovery: Recovery,
    pub value_density: ValueDensity,
    pub vulnerability_response_effort: VulnerabilityResponseEffort,
    pub provider_urgency: ProviderUrgency,
}

fn parse_metric<M>(parts: &mut Peekable<std::str::Split<'_, char>>) -> Result<M, ParseError>
where
    M: CvssMetric + fmt::Debug,
{
    let part = parts.peek().ok_or_else(|| ParseError::Missing)?;
    let (name, val) = part
        .split_once(common::METRIC_DELIM)
        .ok_or_else(|| ParseError::MalformedVector)?;
    if name != M::ABBREVIATED_FORM {
        return Err(ParseError::MalformedVector);
    }
    let metric = M::from_str(val)?;
    let _ = parts.next();
    Ok(metric)
}

fn parse_opt_metric<M>(parts: &mut Peekable<std::str::Split<'_, char>>) -> Result<M, ParseError>
where
    M: CvssMetric + Optional,
{
    let Some(part) = parts.peek() else {
        return Ok(M::default());
    };
    let (name, val) = part
        .split_once(common::METRIC_DELIM)
        .ok_or_else(|| ParseError::MalformedVector)?;
    if name != M::ABBREVIATED_FORM {
        return Ok(M::default());
    }
    let metric = M::from_str(val)?;
    let _ = parts.next();
    Ok(metric)
}

impl FromStr for V4Vector {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix("CVSS:4.0/")
            .ok_or_else(|| ParseError::MalformedVector)?;
        let mut parts = s.split(common::VECTOR_DELIM).peekable();
        let attack_vector: AttackVector = parse_metric(&mut parts)?;
        let attack_complexity: AttackComplexity = parse_metric(&mut parts)?;
        let attack_requirements: AttackRequirements = parse_metric(&mut parts)?;
        let privileges_required: PrivilegesRequired = parse_metric(&mut parts)?;
        let user_interaction: UserInteraction = parse_metric(&mut parts)?;
        let vulnerable_confidentiality: VulnerableSystemConfidentiality = parse_metric(&mut parts)?;
        let vulnerable_integrity: VulnerableSystemIntegrity = parse_metric(&mut parts)?;
        let vulnerable_availability: VulnerableSystemAvailability = parse_metric(&mut parts)?;
        let subsequent_confidentiality: SubsequentSystemConfidentiality = parse_metric(&mut parts)?;
        let subsequent_integrity: SubsequentSystemIntegrity = parse_metric(&mut parts)?;
        let subsequent_availability: SubsequentSystemAvailability = parse_metric(&mut parts)?;

        let exploit_maturity: ExploitMaturity = parse_opt_metric(&mut parts)?;

        let confidentiality_requirement: ConfidentialityRequirement = parse_opt_metric(&mut parts)?;
        let integrity_requirement: IntegrityRequirement = parse_opt_metric(&mut parts)?;
        let availability_requirement: AvailabilityRequirement = parse_opt_metric(&mut parts)?;
        let modified_attack_vector: ModifiedAttackVector = parse_opt_metric(&mut parts)?;
        let modified_attack_complexity: ModifiedAttackComplexity = parse_opt_metric(&mut parts)?;
        let modified_privileges_required: ModifiedPrivilegesRequired =
            parse_opt_metric(&mut parts)?;
        let modified_user_interaction: ModifiedUserInteraction = parse_opt_metric(&mut parts)?;
        let modified_vulnerable_confidentiality: ModifiedVulnerableSystemConfidentiality =
            parse_opt_metric(&mut parts)?;
        let modified_vulnerable_integrity: ModifiedVulnerableSystemIntegrity =
            parse_opt_metric(&mut parts)?;
        let modified_vulnerable_availability: ModifiedVulnerableSystemAvailability =
            parse_opt_metric(&mut parts)?;
        let modified_subsequent_confidentiality: ModifiedSubsequentSystemConfidentiality =
            parse_opt_metric(&mut parts)?;
        let modified_subsequent_integrity: ModifiedSubsequentSystemIntegrity =
            parse_opt_metric(&mut parts)?;
        let modified_subsequent_availability: ModifiedSubsequentSystemAvailability =
            parse_opt_metric(&mut parts)?;

        let safety: Safety = parse_opt_metric(&mut parts)?;
        let automatable: Automatable = parse_opt_metric(&mut parts)?;
        let recovery: Recovery = parse_opt_metric(&mut parts)?;
        let value_density: ValueDensity = parse_opt_metric(&mut parts)?;
        let vulnerability_response_effort: VulnerabilityResponseEffort =
            parse_opt_metric(&mut parts)?;
        let provider_urgency: ProviderUrgency = parse_opt_metric(&mut parts)?;
        Ok(Self {
            attack_vector,
            attack_complexity,
            attack_requirements,
            privileges_required,
            user_interaction,
            vulnerable_confidentiality,
            vulnerable_integrity,
            vulnerable_availability,
            subsequent_confidentiality,
            subsequent_integrity,
            subsequent_availability,
            exploit_maturity,
            confidentiality_requirement,
            integrity_requirement,
            availability_requirement,
            modified_attack_vector,
            modified_attack_complexity,
            modified_privileges_required,
            modified_user_interaction,
            modified_vulnerable_confidentiality,
            modified_vulnerable_integrity,
            modified_vulnerable_availability,
            modified_subsequent_confidentiality,
            modified_subsequent_integrity,
            modified_subsequent_availability,
            safety,
            automatable,
            recovery,
            value_density,
            vulnerability_response_effort,
            provider_urgency,
        })
    }
}

impl V4Vector {
    pub fn new(
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        attack_requirements: AttackRequirements,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction,
        vulnerable_confidentiality: VulnerableSystemConfidentiality,
        vulnerable_integrity: VulnerableSystemIntegrity,
        vulnerable_availability: VulnerableSystemAvailability,
        subsequent_confidentiality: SubsequentSystemConfidentiality,
        subsequent_integrity: SubsequentSystemIntegrity,
        subsequent_availability: SubsequentSystemAvailability,
    ) -> Self {
        Self {
            attack_vector,
            attack_complexity,
            attack_requirements,
            privileges_required,
            user_interaction,
            vulnerable_confidentiality,
            vulnerable_integrity,
            vulnerable_availability,
            subsequent_confidentiality,
            subsequent_integrity,
            subsequent_availability,
            exploit_maturity: Default::default(),
            confidentiality_requirement: Default::default(),
            integrity_requirement: Default::default(),
            availability_requirement: Default::default(),
            modified_attack_vector: Default::default(),
            modified_attack_complexity: Default::default(),
            modified_privileges_required: Default::default(),
            modified_user_interaction: Default::default(),
            modified_vulnerable_confidentiality: Default::default(),
            modified_vulnerable_integrity: Default::default(),
            modified_vulnerable_availability: Default::default(),
            modified_subsequent_confidentiality: Default::default(),
            modified_subsequent_integrity: Default::default(),
            modified_subsequent_availability: Default::default(),
            safety: Default::default(),
            automatable: Default::default(),
            recovery: Default::default(),
            value_density: Default::default(),
            vulnerability_response_effort: Default::default(),
            provider_urgency: Default::default(),
        }
    }

    /// Output the minimum vector, with optional Not Defined metrics omited.
    ///
    /// This is the same as `format!("{}", vector)`
    pub fn to_string_minimum(&self) -> String {
        self.to_string()
    }

    /// Output the complete vector, without omitting any metrics
    ///
    /// This is the same as `format!("{:#}", vector)`
    pub fn to_string_full(&self) -> String {
        format!("{self:#}")
    }

    fn eqs(&self) -> Equations {
        Equations::new(self)
    }

    /// The CVSSv4 score computed based on the rules laid out
    /// [here](https://www.first.org/cvss/v4.0/specification-document#CVSS-v4-0-Scoring)
    pub fn score(&self) -> Score {
        self.eqs().score()
    }

    /// Parse and add threat metrics to the vector
    pub fn extend_with_threat(&mut self, threat: &str) -> Result<(), ParseError> {
        let mut parts = threat.split(common::VECTOR_DELIM).peekable();
        self.exploit_maturity = parse_metric(&mut parts)?;
        Ok(())
    }

    /// Reset the threat metrics to their default "not defined" state
    pub fn clear_threat(&mut self) {
        self.exploit_maturity = Default::default();
    }

    /// Reset the environmental metrics to their default "not defined" state
    pub fn clear_environmental(&mut self) {
        self.confidentiality_requirement = Default::default();
        self.integrity_requirement = Default::default();
        self.availability_requirement = Default::default();
        self.modified_attack_vector = Default::default();
        self.modified_attack_complexity = Default::default();
        self.modified_privileges_required = Default::default();
        self.modified_user_interaction = Default::default();
        self.modified_vulnerable_confidentiality = Default::default();
        self.modified_vulnerable_integrity = Default::default();
        self.modified_vulnerable_availability = Default::default();
        self.modified_subsequent_confidentiality = Default::default();
        self.modified_subsequent_integrity = Default::default();
        self.modified_subsequent_availability = Default::default();
    }

    /// Reset the supplemental metrics to their default "not defined" state
    pub fn clear_supplemental(&mut self) {
        self.safety = Default::default();
        self.automatable = Default::default();
        self.recovery = Default::default();
        self.value_density = Default::default();
        self.vulnerability_response_effort = Default::default();
        self.provider_urgency = Default::default();
    }
}

fn fmt_metric<M: CvssMetric>(metric: M, f: &mut fmt::Formatter<'_>, first: bool) -> fmt::Result {
    use fmt::Write;
    if !first {
        f.write_char(crate::common::VECTOR_DELIM)?;
    }
    f.write_str(M::ABBREVIATED_FORM)?;
    f.write_char(crate::common::METRIC_DELIM)?;
    f.write_str(metric.as_str())
}

fn fmt_opt_metric<M: CvssMetric + Optional>(metric: M, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    use fmt::Write;
    if !metric.is_undefined() || f.alternate() {
        f.write_str(M::ABBREVIATED_FORM)?;
        f.write_char(crate::common::METRIC_DELIM)?;
        f.write_str(metric.as_str())?;
    }
    Ok(())
}

impl fmt::Display for V4Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        macro_rules! write_metric {
            ($field:ident) => {
                fmt_metric(self.$field, f, false)
            };
            ($field:ident ?) => {
                fmt_opt_metric(self.$field, f)
            };
        }
        fmt_metric(self.attack_vector, f, true)?;
        write_metric!(attack_complexity)?;
        write_metric!(attack_requirements)?;
        write_metric!(privileges_required)?;
        write_metric!(user_interaction)?;
        write_metric!(vulnerable_confidentiality)?;
        write_metric!(vulnerable_integrity)?;
        write_metric!(vulnerable_availability)?;
        write_metric!(subsequent_confidentiality)?;
        write_metric!(subsequent_integrity)?;
        write_metric!(subsequent_availability)?;

        write_metric!(exploit_maturity?)?;
        write_metric!(confidentiality_requirement?)?;
        write_metric!(integrity_requirement?)?;
        write_metric!(availability_requirement?)?;
        write_metric!(modified_attack_vector?)?;
        write_metric!(modified_attack_complexity?)?;
        write_metric!(modified_privileges_required?)?;
        write_metric!(modified_user_interaction?)?;
        write_metric!(modified_vulnerable_confidentiality?)?;
        write_metric!(modified_vulnerable_integrity?)?;
        write_metric!(modified_vulnerable_availability?)?;
        write_metric!(modified_subsequent_confidentiality?)?;
        write_metric!(modified_subsequent_integrity?)?;
        write_metric!(modified_subsequent_availability?)?;
        write_metric!(safety?)?;
        write_metric!(automatable?)?;
        write_metric!(recovery?)?;
        write_metric!(value_density?)?;
        write_metric!(vulnerability_response_effort?)?;
        write_metric!(provider_urgency?)
    }
}

pub(crate) trait V4Metric {
    fn level(&self) -> i8;
    fn distance(&self, other: &Self) -> i8 {
        self.level() - other.level()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! test_score {
        ($cvss_str:literal, $exp:literal) => {{
            let cvss: V4Vector = $cvss_str.parse().unwrap();
            let cvss_score = cvss.score();
            assert_eq!(cvss_score, Score($exp), "score mismatch for {}", $cvss_str);
        }};
    }

    #[test]
    fn cve_2022_41741() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            7.3
        );
    }
    #[test]
    fn cve_2020_3549() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            7.7
        );
    }
    #[test]
    fn cve_2020_3549_environmental() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
            5.2
        );
    }
    #[test]
    fn cve_2023_3089() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
            8.3
        );
    }

    #[test]
    fn cve_2023_3089_environmental() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
            8.1
        );
    }

    #[test]
    fn cve_2021_44714() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            4.6
        )
    }

    #[test]
    fn cve_2022_21830() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            5.1
        )
    }

    #[test]
    fn cve_2022_22186() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
            6.9
        )
    }

    #[test]
    fn cve_2023_21989() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
            5.9
        )
    }

    #[test]
    fn cve_2020_3947() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            9.4
        )
    }

    #[test]
    fn cve_2023_30560() {
        test_score!(
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D",
            8.3
        )
    }

    #[test]
    fn cve_2014_0160() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A",
            8.7
        )
    }

    #[test]
    fn cve_2014_6271() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A",
            9.3
        )
    }
    #[test]
    fn cve_2021_44228() {
        test_score!(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
            10.0
        )
    }

    #[test]
    fn cve_2013_6014() {
        test_score!(
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H",
            6.4
        )
    }

    #[test]
    fn cve_2016_5729() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I",
            9.3
        )
    }

    #[test]
    fn cve_2015_2890() {
        test_score!(
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I",
            8.7
        )
    }

    #[test]
    fn cve_2018_3652() {
        test_score!(
            "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            8.6
        )
    }
}
