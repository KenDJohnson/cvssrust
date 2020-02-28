pub mod base;
pub mod env;
pub mod score;
pub mod temporal;

use super::common::{append_metric, append_metric_optional, parse_metrics, ParseError};
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Debug)]
pub struct V2Vector {
    pub access_vector: base::AccessVector,
    pub access_complexity: base::AccessComplexity,
    pub authentication: base::Authentication,
    pub confidentiality_impact: base::ConfidentialityImpact,
    pub integrity_impact: base::IntegrityImpact,
    pub availability_impact: base::AvailabilityImpact,

    pub exploitability: temporal::Exploitability,
    pub remediation_level: temporal::RemediationLevel,
    pub report_confidence: temporal::ReportConfidence,

    pub collateral_damage_potential: env::CollateralDamagePotential,
    pub target_distribution: env::TargetDistribution,
    pub confidentiality_requirement: env::ConfidentialityRequirement,
    pub integrity_requirement: env::IntegrityRequirement,
    pub availability_requirement: env::AvailabilityRequirement,
}

impl V2Vector {
    #[rustfmt::skip]
    pub fn new(
        access_vector: base::AccessVector,
        access_complexity: base::AccessComplexity,
        authentication: base::Authentication,
        confidentiality_impact: base::ConfidentialityImpact,
        integrity_impact: base::IntegrityImpact,
        availability_impact: base::AvailabilityImpact,
    ) -> V2Vector {
        V2Vector{
            access_vector,
            access_complexity,
            authentication,
            confidentiality_impact,
            integrity_impact,
            availability_impact,

            exploitability:    temporal::Exploitability::NotDefined,
            remediation_level: temporal::RemediationLevel::NotDefined,
            report_confidence: temporal::ReportConfidence::NotDefined,

            collateral_damage_potential: env::CollateralDamagePotential::NotDefined,
            target_distribution:         env::TargetDistribution::NotDefined,
            confidentiality_requirement: env::ConfidentialityRequirement::NotDefined,
            integrity_requirement:       env::IntegrityRequirement::NotDefined,
            availability_requirement:    env::AvailabilityRequirement::NotDefined,
        }
    }

    fn as_string(&self) -> String {
        let mut vector = String::from("");

        append_metric(&mut vector, "AV", &self.access_vector);
        append_metric(&mut vector, "AC", &self.access_complexity);
        append_metric(&mut vector, "Au", &self.authentication);
        append_metric(&mut vector, "C", &self.confidentiality_impact);
        append_metric(&mut vector, "I", &self.integrity_impact);
        append_metric(&mut vector, "A", &self.availability_impact);

        append_metric_optional(&mut vector, "E", &self.exploitability);
        append_metric_optional(&mut vector, "RL", &self.remediation_level);
        append_metric_optional(&mut vector, "RC", &self.report_confidence);

        append_metric_optional(&mut vector, "CDP", &self.collateral_damage_potential);
        append_metric_optional(&mut vector, "TD", &self.target_distribution);
        append_metric_optional(&mut vector, "CR", &self.confidentiality_requirement);
        append_metric_optional(&mut vector, "IR", &self.integrity_requirement);
        append_metric_optional(&mut vector, "AR", &self.availability_requirement);

        vector
    }

    /// Parse a CVSS 2 string and return V2Vector.
    // TODO: check for invalid(unknown) metrics
    // TODO: remove round brackets ()
    #[rustfmt::skip]
    fn parse(cvss_str: &str) -> Result<Self, ParseError> {
        let parsed = parse_metrics(cvss_str)?;

        let access_vector =          base::AccessVector          ::from_str(parsed.get("AV").ok_or_else(|| ParseError::Missing)?)?;
        let access_complexity =      base::AccessComplexity      ::from_str(parsed.get("AC").ok_or_else(|| ParseError::Missing)?)?;
        let authentication =         base::Authentication        ::from_str(parsed.get("Au").ok_or_else(|| ParseError::Missing)?)?;
        let confidentiality_impact = base::ConfidentialityImpact ::from_str(parsed.get("C").ok_or_else(|| ParseError::Missing)?)?;
        let integrity_impact =       base::IntegrityImpact       ::from_str(parsed.get("I").ok_or_else(|| ParseError::Missing)?)?;
        let availability_impact =    base::AvailabilityImpact    ::from_str(parsed.get("A").ok_or_else(|| ParseError::Missing)?)?;

        // Create a vector
        let mut vector = V2Vector::new(
            access_vector,
            access_complexity,
            authentication,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
        );

        const ND: &str = "ND";

        vector.exploitability =    temporal::Exploitability   ::from_str(parsed.get("E").unwrap_or(&ND))?;
        vector.remediation_level = temporal::RemediationLevel ::from_str(parsed.get("RL").unwrap_or(&ND))?;
        vector.report_confidence = temporal::ReportConfidence ::from_str(parsed.get("RC").unwrap_or(&ND))?;

        vector.collateral_damage_potential = env::CollateralDamagePotential  ::from_str(parsed.get("CDP").unwrap_or(&ND))?;
        vector.target_distribution =         env::TargetDistribution         ::from_str(parsed.get("TD").unwrap_or(&ND))?;
        vector.confidentiality_requirement = env::ConfidentialityRequirement ::from_str(parsed.get("CR").unwrap_or(&ND))?;
        vector.integrity_requirement =       env::IntegrityRequirement       ::from_str(parsed.get("IR").unwrap_or(&ND))?;
        vector.availability_requirement =    env::AvailabilityRequirement    ::from_str(parsed.get("AR").unwrap_or(&ND))?;

        Ok(vector)
    }
}

impl Display for V2Vector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for V2Vector {
    type Err = ParseError;

    fn from_str(cvss_str: &str) -> Result<Self, Self::Err> {
        V2Vector::parse(cvss_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_v2() {
        let cvss_str = "AV:N/AC:M/Au:N/C:P/I:P/A:N";
        let vector = V2Vector::from_str(cvss_str).unwrap();
        assert_eq!(vector.to_string(), cvss_str);
    }

    #[test]
    fn test_parse_v2_temp_env() {
        let cvss_str = "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
        let vector = V2Vector::from_str(cvss_str).unwrap();
        assert_eq!(vector.to_string(), cvss_str);
    }
}