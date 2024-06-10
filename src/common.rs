use std::collections::HashMap;
use std::fmt;

pub const METRIC_DELIM: char = ':';
pub const VECTOR_DELIM: char = '/';

/// CVSS Score implementation: Base/Temporal/Environmental
pub trait CVSSScore {
    /// Calculate CVSS Base Score
    fn base_score(&self) -> Score;

    /// Calculate CVSS Temporal Score
    fn temporal_score(&self) -> Score;

    /// Calculate CVSS Environmental Score
    fn environmental_score(&self) -> Score;

    /// Calculate Impact Sub Score
    fn impact_score(&self) -> Score;

    /// Calculate Exploitability Score
    fn expoitability_score(&self) -> Score;
}

/// Base/Temporal/Environmental CVSS Score
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Default, PartialEq, PartialOrd)]
pub struct Score(pub(crate) f64);

impl Score {
    pub fn value(self) -> f64 {
        self.0
    }

    pub fn severity(self) -> Severity {
        Severity::from_score(self)
    }
}

impl From<f64> for Score {
    fn from(score: f64) -> Score {
        Score(score)
    }
}

impl From<Score> for f64 {
    fn from(score: Score) -> f64 {
        score.value()
    }
}

/// Qualitative Severity Rating Scale
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn from(s: f64) -> Severity {
        match s {
            s if s < 0.1 => Severity::None,
            s if s >= 0.1 && s < 4.0 => Severity::Low,
            s if s >= 4.0 && s < 7.0 => Severity::Medium,
            s if s >= 7.0 && s < 9.0 => Severity::High,
            s if s >= 9.0 => Severity::Critical,
            _ => Severity::Critical,
        }
    }

    pub fn from_score(s: Score) -> Severity {
        Severity::from(s.value())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Severity::None => "None",
                Severity::Low => "Low",
                Severity::Medium => "Medium",
                Severity::High => "High",
                Severity::Critical => "Critical",
            }
        )
    }
}

/// Parsing error type
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ParseError {
    MalformedVector,
    Missing,
    Duplicated,
    IncorrectValue,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CVSS parse error")
    }
}

macro_rules! optional_metric {
    ($t:ident :: $v:ident) => {
        impl $crate::common::Optional for $t {
            fn is_undefined(&self) -> bool {
                matches!(self, $t::$v)
            }
        }

        impl Default for $t {
            fn default() -> Self {
                Self::$v
            }
        }
    };
}
pub(crate) use optional_metric;

pub trait Optional: Default {
    fn is_undefined(&self) -> bool;
}

pub trait NumValue {
    fn num_value(&self) -> f64 {
        0.0
    }
    fn num_value_scoped(&self, _scope_change: bool) -> f64 {
        0.0
    }
}

/// Append metric and its value to a vector string.
pub fn append_metric<T: AsRef<str>>(vector: &mut String, metric: &str, value: &T) {
    if !vector.is_empty() {
        vector.push(VECTOR_DELIM);
    }
    vector.push_str(metric);
    vector.push(METRIC_DELIM);
    vector.push_str(value.as_ref());
}

/// Append metric and its value to a vector string if it is not undefined (for optionsl metrics).
pub fn append_metric_optional<T: AsRef<str> + Optional>(
    vector: &mut String,
    metric: &str,
    value: &T,
) {
    if !value.is_undefined() {
        append_metric(vector, metric, value);
    }
}

/// Parse CVSS vector and return metrics as a hash map of strings.
pub fn parse_metrics(cvss_str: &str) -> Result<HashMap<&str, &str>, ParseError> {
    let mut parsed = HashMap::new();

    for vector_part in cvss_str.split(VECTOR_DELIM) {
        let mut metric_parts = vector_part.split(METRIC_DELIM);
        let metric = metric_parts
            .next()
            .ok_or_else(|| ParseError::MalformedVector)?;
        let value = metric_parts
            .next()
            .ok_or_else(|| ParseError::MalformedVector)?;
        if metric_parts.next().is_some() {
            return Err(ParseError::MalformedVector);
        }

        if parsed.contains_key(metric) {
            return Err(ParseError::Duplicated);
        }
        parsed.insert(metric, value);
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score() {
        assert_eq!(Severity::from_score(Score(0.0)), Severity::None);
        assert_eq!(Severity::from_score(Score(3.9)), Severity::Low);
        assert_eq!(Severity::from_score(Score(3.95)), Severity::Low);
        assert_eq!(Severity::from_score(Score(4.0)), Severity::Medium);
        assert_eq!(Severity::from_score(Score(4.01)), Severity::Medium);
        assert_eq!(Severity::from_score(Score(7.89)), Severity::High);
        assert_eq!(Severity::from_score(Score(9.12)), Severity::Critical);
        assert_eq!(Severity::from_score(Score(102.3)), Severity::Critical);
    }

    #[test]
    fn test_score_severity() {
        assert_eq!(Score(4.5).severity(), Severity::Medium);
    }
}

pub trait CvssMetric: std::str::FromStr<Err = ParseError> {
    const METRIC_NAME: &'static str;
    const ABBREVIATED_FORM: &'static str;
    // const VALUES: &'static [&'static str];

    fn as_str(&self) -> &'static str;
}

macro_rules! cvss_metric {
    ($(#[$attr:meta])* $pub:vis enum $t:ident $name:literal $short:literal { $( $(#[$vattr:meta])* $variant:ident : $num:literal => $s:literal ),+ $(,)? }) => {
        $(#[$attr])*
        $pub enum $t {
            $($(#[$vattr])* $variant),+

        }

        impl $crate::common::CvssMetric for $t {
            const METRIC_NAME: &'static str = $name;
            const ABBREVIATED_FORM: &'static str = $short;
            // const VALUES: &'static [&'static str];

            fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $s,)+
                }
            }
        }

        impl std::str::FromStr for $t {
            type Err = $crate::common::ParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($s => Ok(Self::$variant),)+
                    _ => Err($crate::common::ParseError::IncorrectValue),
                }
            }
        }

        impl AsRef<str> for $t {
            fn as_ref(&self) -> &str {
                $crate::common::CvssMetric::as_str(self)
            }
        }

        impl $crate::v4::V4Metric for $t {
            // fn distance(&self, other: &Self) -> i8 {
            //     let self_num = (*self) as u8 as i8;
            //     let other_num = (*other) as u8 as i8;
            //     self_num - other_num
            //     // if self_num > other_num {
            //     //     self_num - other_num
            //     // } else {
            //     //     other_num - self_num
            //     // }
            // }
            fn level(&self) -> i8 {
                match self {
                    $(Self::$variant => $num),+
                }
            }
        }
    };
}
pub(crate) use cvss_metric;
