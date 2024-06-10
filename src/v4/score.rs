use crate::Score;

use super::{
    base::{
        AttackComplexity, AttackRequirements, AttackVector, PrivilegesRequired,
        SubsequentSystemAvailability, SubsequentSystemConfidentiality, SubsequentSystemIntegrity,
        UserInteraction, VulnerableSystemAvailability, VulnerableSystemConfidentiality,
        VulnerableSystemIntegrity,
    },
    env::{
        AvailabilityRequirement, ConfidentialityRequirement, IntegrityRequirement,
        ModifiedSubsequentSystemAvailability, ModifiedSubsequentSystemIntegrity,
    },
    threat::ExploitMaturity,
    V4Metric, V4Vector,
};

pub type EquationLevel = u8;
pub type EquationLevelArray = [EquationLevel; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Equations {
    eq1: Eq1,
    eq2: Eq2,
    eq3: Eq3,
    eq4: Eq4,
    eq5: Eq5,
    eq6: Eq6,
}

impl Equations {
    pub(super) fn new(vector: &V4Vector) -> Self {
        Self {
            eq1: Eq1::new(vector),
            eq2: Eq2::new(vector),
            eq3: Eq3::new(vector),
            eq4: Eq4::new(vector),
            eq5: Eq5::new(vector),
            eq6: Eq6::new(vector),
        }
    }
    pub(super) fn levels_array(&self) -> EquationLevelArray {
        [
            self.eq1.level(),
            self.eq2.level(),
            self.eq3.level(),
            self.eq4.level(),
            self.eq5.level(),
            self.eq6.level(),
        ]
    }

    fn severity_distances(&self) -> [f64; 5] {
        let eq3 = self.eq3.distance_from_highest() as f64;
        let eq6 = self.eq6.distance_from_highest() as f64;

        [
            self.eq1.distance_from_highest() as f64,
            self.eq2.distance_from_highest() as f64,
            eq3.max(eq6),
            self.eq4.distance_from_highest() as f64,
            0.0,
        ]
    }
    fn proportion_distances(&self, score_dists: [Option<f64>; 6]) -> ([f64; 5], [Option<f64>; 5]) {
        let mut combined_score = [None; 5];
        combined_score[0] = score_dists[0];
        combined_score[1] = score_dists[1];
        combined_score[3] = score_dists[3];
        combined_score[4] = score_dists[4];
        let mut distances = dbg!(self.severity_distances());
        distances[0] /= Eq1::level_depth(self.eq1.level()) as f64;
        distances[1] /= Eq2::level_depth(self.eq2.level()) as f64;

        match (score_dists[2], score_dists[5]) {
            (Some(eq3), Some(eq6)) => {
                combined_score[2] = Some(eq3.max(eq6));
                distances[2] /= Eq3::level_depth(self.eq3.level())
                    .max(Eq6::level_depth(self.eq6.level())) as f64;
            }
            (Some(eq3), None) => {
                combined_score[2] = Some(eq3);
                distances[2] /= Eq3::level_depth(self.eq3.level()) as f64;
            }
            (None, Some(eq6)) => {
                combined_score[2] = Some(eq6);
                distances[2] /= Eq6::level_depth(self.eq6.level()) as f64;
            }
            (None, None) => (),
        }

        distances[3] /= Eq4::level_depth(self.eq4.level()) as f64;
        distances[4] /= Eq5::level_depth(self.eq5.level()) as f64;
        (distances, combined_score)
    }

    fn scoring_distance(base: f64, eqs: EquationLevelArray, idx: usize) -> Option<f64> {
        let new = if matches!(idx, 0 | 2 | 3 | 4) && eqs[idx] < 2
            || matches!(idx, 1 | 5) && eqs[idx] < 1
        {
            let mut new = eqs;
            new[idx] = new[idx] + 1;
            new
        } else {
            return None;
        };
        Some(base - base_score(validate_eqs(new)?).0)
    }

    fn scoring_distances(base: f64, eqs: EquationLevelArray) -> [Option<f64>; 6] {
        [
            Self::scoring_distance(base, eqs, 0),
            Self::scoring_distance(base, eqs, 1),
            Self::scoring_distance(base, eqs, 2),
            Self::scoring_distance(base, eqs, 3),
            Self::scoring_distance(base, eqs, 4),
            Self::scoring_distance(base, eqs, 5),
        ]
    }

    pub(super) fn score(&self) -> Score {
        let eqs = dbg!(self.levels_array());
        let base = dbg!(base_score(eqs));
        let score_dists = dbg!(Self::scoring_distances(base.0, eqs));
        let (prop_dist, score_dists) = dbg!(self.proportion_distances(score_dists));
        let mut count = 0;
        let total: f64 = score_dists
            .iter()
            .zip(prop_dist)
            .filter_map(|(score, prop)| {
                score.map(|d| {
                    count += 1;
                    d * prop
                })
            })
            .sum();
        let diff = (((total / count as f64) * 10.0).round()) / 10.0;
        Score(base.0 - diff)
    }
}
const MAX_EQS: EquationLevelArray = [
    Eq1::MAX_LEVEL,
    Eq2::MAX_LEVEL,
    Eq3::MAX_LEVEL,
    Eq4::MAX_LEVEL,
    Eq5::MAX_LEVEL,
    Eq6::MAX_LEVEL,
];
fn validate_eqs(eqs: EquationLevelArray) -> Option<EquationLevelArray> {
    if eqs.iter().zip(MAX_EQS.iter()).all(|(eq, max)| eq <= max)
        && !matches!((eqs[2], eqs[5]), (2, 0))
    {
        Some(eqs)
    } else {
        None
    }
}

pub(super) trait Equation: Copy + 'static {
    const MAX_LEVEL: u8;
    const HIGHEST_VECTORS: &'static [&'static [Self]];
    fn new(vector: &V4Vector) -> Self;
    fn highest_vectors(level: EquationLevel) -> &'static [Self]
    where
        Self: Sized,
    {
        assert!(
            level <= Self::MAX_LEVEL,
            "invalid level {} for {}",
            level,
            std::any::type_name::<Self>()
        );
        Self::HIGHEST_VECTORS[level as usize]
    }
    fn level(&self) -> EquationLevel;
    fn level_depth(level: EquationLevel) -> u8;
    fn distance(&self, other: &Self) -> i8;
    fn distance_from_highest(&self) -> i8
    where
        Self: Sized + 'static,
    {
        Self::highest_vectors(self.level())
            .iter()
            .map(|eq| self.distance(eq))
            .max()
            .unwrap()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq1 {
    av: AttackVector,
    pr: PrivilegesRequired,
    ui: UserInteraction,
}
impl Eq1 {
    const fn build(av: AttackVector, pr: PrivilegesRequired, ui: UserInteraction) -> Self {
        Self { av, pr, ui }
    }
}

impl Equation for Eq1 {
    const MAX_LEVEL: u8 = 2;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(AV![N], PR![N], UI![N])],
        &[
            Self::build(AV![A], PR![N], UI![N]),
            Self::build(AV![N], PR![L], UI![N]),
            Self::build(AV![N], PR![N], UI![P]),
        ],
        &[
            Self::build(AV![P], PR![N], UI![N]),
            Self::build(AV![A], PR![L], UI![P]),
        ],
    ];
    fn new(vector: &V4Vector) -> Self {
        let V4Vector {
            attack_vector: av,
            privileges_required: pr,
            user_interaction: ui,
            ..
        } = *vector;
        Self { av, pr, ui }
    }
    fn level(&self) -> EquationLevel {
        let Self { av, pr, ui } = *self;
        if matches!((av, pr, ui), (AV![N], PR![N], UI![N])) {
            0
        } else if (av == AV![N] || pr == PR![N] || ui == UI![N]) && av != AV![P] {
            1
        } else {
            2
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 1,
            1 => 4,
            2 => 5,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        self.av.distance(&other.av) + self.pr.distance(&other.pr) + self.ui.distance(&other.ui)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq2 {
    ac: AttackComplexity,
    at: AttackRequirements,
}
impl Eq2 {
    const fn build(ac: AttackComplexity, at: AttackRequirements) -> Self {
        Self { ac, at }
    }
}
impl Equation for Eq2 {
    const MAX_LEVEL: u8 = 1;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(AC![L], AT![N])],
        &[Self::build(AC![L], AT![P]), Self::build(AC![H], AT![N])],
    ];
    fn new(vector: &V4Vector) -> Self {
        let V4Vector {
            attack_complexity: ac,
            attack_requirements: at,
            ..
        } = *vector;
        Self { ac, at }
    }
    fn level(&self) -> EquationLevel {
        let Self { ac, at } = *self;
        if ac == AC![L] && at == AT![N] {
            0
        } else {
            1
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 1,
            1 => 2,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        self.ac.distance(&other.ac) + self.at.distance(&other.at)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq3 {
    vc: VulnerableSystemConfidentiality,
    vi: VulnerableSystemIntegrity,
    va: VulnerableSystemAvailability,
}
impl Eq3 {
    const fn build(
        vc: VulnerableSystemConfidentiality,
        vi: VulnerableSystemIntegrity,
        va: VulnerableSystemAvailability,
    ) -> Self {
        Self { vc, vi, va }
    }
}
impl Equation for Eq3 {
    const MAX_LEVEL: u8 = 2;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(VC![H], VI![H], VA![H])],
        &[
            Self::build(VC![L], VI![H], VA![H]),
            Self::build(VC![H], VI![L], VA![H]),
        ],
        &[Self::build(VC![L], VI![L], VA![L])],
    ];
    fn new(vector: &V4Vector) -> Self {
        let V4Vector {
            vulnerable_availability: va,
            vulnerable_confidentiality: vc,
            vulnerable_integrity: vi,
            ..
        } = *vector;
        Self { va, vc, vi }
    }
    fn level(&self) -> EquationLevel {
        let Self { va, vc, vi } = *self;
        if vc == VC![H] && vi == VI![H] {
            0
        } else if vc == VC![H] || vi == VI![H] || va == VA![H] {
            1
        } else {
            2
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 3,
            1 => 4,
            2 => 4,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        self.va.distance(&other.va) + self.vc.distance(&other.vc) + self.vi.distance(&other.vi)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq4 {
    msi: Option<ModifiedSubsequentSystemIntegrity>,
    msa: Option<ModifiedSubsequentSystemAvailability>,
    sc: SubsequentSystemConfidentiality,
    si: SubsequentSystemIntegrity,
    sa: SubsequentSystemAvailability,
}
impl Eq4 {
    const fn build(
        msi: Option<ModifiedSubsequentSystemIntegrity>,
        msa: Option<ModifiedSubsequentSystemAvailability>,
        sc: SubsequentSystemConfidentiality,
        si: SubsequentSystemIntegrity,
        sa: SubsequentSystemAvailability,
    ) -> Self {
        Self {
            msi,
            msa,
            sc,
            si,
            sa,
        }
    }
}
impl Equation for Eq4 {
    const MAX_LEVEL: u8 = 2;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(
            Some(MSI![S]),
            Some(MSA![S]),
            SC![H],
            SI![H],
            SA![H],
        )],
        &[Self::build(None, None, SC![H], SI![H], SA![H])],
        &[Self::build(None, None, SC![L], SI![L], SA![L])],
    ];
    fn new(vector: &V4Vector) -> Self {
        let msi = if vector.modified_subsequent_integrity == MSI![S] {
            Some(vector.modified_subsequent_integrity)
        } else {
            None
        };
        let msa = if vector.modified_subsequent_availability == MSA![S] {
            Some(vector.modified_subsequent_availability)
        } else {
            None
        };
        Self {
            msi,
            msa,
            si: vector.subsequent_integrity,
            sa: vector.subsequent_availability,
            sc: vector.subsequent_confidentiality,
        }
    }
    fn level(&self) -> EquationLevel {
        if self.msi.is_some() || self.msa.is_some() {
            return 0;
        }
        let Self { si, sa, sc, .. } = *self;
        if sc == SC![H] || si == SI![H] || sa == SA![H] {
            1
        } else {
            2
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 6,
            1 => 5,
            2 => 4,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        // no need to check MSI/MSA, if they're present they'll both be S, so there's a distance of 0
        self.si.distance(&other.si) + self.sa.distance(&other.sa) + self.sc.distance(&other.sc)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq5 {
    e: ExploitMaturity,
}
impl Eq5 {
    const fn build(e: ExploitMaturity) -> Self {
        Self { e }
    }
}
impl Equation for Eq5 {
    const MAX_LEVEL: u8 = 2;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(E![A])],
        &[Self::build(E![P])],
        &[Self::build(E![U])],
    ];
    fn new(vector: &V4Vector) -> Self {
        Self {
            e: vector.exploit_maturity,
        }
    }
    fn level(&self) -> EquationLevel {
        match self.e {
            E![A] | E![X] => 0,
            E![P] => 1,
            E![U] => 2,
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 1,
            1 => 1,
            2 => 1,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        self.e.distance(&other.e)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Eq6 {
    cr: ConfidentialityRequirement,
    ir: IntegrityRequirement,
    ar: AvailabilityRequirement,
    vc: VulnerableSystemConfidentiality,
    vi: VulnerableSystemIntegrity,
    va: VulnerableSystemAvailability,
}
impl Eq6 {
    const fn build(
        cr: ConfidentialityRequirement,
        ir: IntegrityRequirement,
        ar: AvailabilityRequirement,
        vc: VulnerableSystemConfidentiality,
        vi: VulnerableSystemIntegrity,
        va: VulnerableSystemAvailability,
    ) -> Self {
        Self {
            cr,
            ir,
            ar,
            vc,
            vi,
            va,
        }
    }
}
impl Equation for Eq6 {
    const MAX_LEVEL: u8 = 1;
    const HIGHEST_VECTORS: &'static [&'static [Self]] = &[
        &[Self::build(CR![H], IR![H], AR![H], VC![H], VI![H], VA![H])],
        &[
            Self::build(CR![M], IR![M], AR![M], VC![H], VI![H], VA![H]),
            Self::build(CR![M], IR![M], AR![H], VC![H], VI![H], VA![L]),
            Self::build(CR![M], IR![H], AR![M], VC![H], VI![L], VA![H]),
            Self::build(CR![M], IR![H], AR![H], VC![H], VI![L], VA![L]),
            Self::build(CR![H], IR![M], AR![M], VC![L], VI![H], VA![H]),
            Self::build(CR![H], IR![M], AR![H], VC![L], VI![H], VA![L]),
            Self::build(CR![H], IR![H], AR![M], VC![L], VI![L], VA![H]),
            Self::build(CR![H], IR![H], AR![H], VC![L], VI![L], VA![L]),
        ],
    ];
    fn new(vector: &V4Vector) -> Self {
        let V4Vector {
            confidentiality_requirement: cr,
            integrity_requirement: ir,
            availability_requirement: ar,
            vulnerable_confidentiality: vc,
            vulnerable_integrity: vi,
            vulnerable_availability: va,
            ..
        } = *vector;
        Self {
            cr,
            ir,
            ar,
            vc,
            vi,
            va,
        }
    }
    fn level(&self) -> EquationLevel {
        let Self {
            cr,
            ir,
            ar,
            vc,
            vi,
            va,
        } = *self;
        match (cr, vc, ir, vi, ar, va) {
            (CR![H], VC![H], _, _, _, _)
            | (CR![X], VC![H], _, _, _, _)
            | (_, _, IR![H], VI![H], _, _)
            | (_, _, IR![X], VI![H], _, _)
            | (_, _, _, _, AR![H], VA![H])
            | (_, _, _, _, AR![X], VA![H]) => 0,
            _ => 1,
        }
    }
    fn level_depth(level: EquationLevel) -> u8 {
        match level {
            0 => 10,
            1 => 10,
            _ => unreachable!(),
        }
    }
    fn distance(&self, other: &Self) -> i8 {
        self.cr.distance(&other.cr)
            + self.ir.distance(&other.ir)
            + self.ar.distance(&other.ar)
            + self.vc.distance(&other.vc)
            + self.vi.distance(&other.vi)
            + self.va.distance(&other.va)
    }
}

fn base_score(eqs: [u8; 6]) -> Score {
    match eqs {
        [0, 0, 0, 0, 0, 0] | [0, 0, 0, 1, 0, 0] => Score(10.0),
        [0, 0, 0, 0, 0, 1] | [0, 1, 0, 0, 0, 0] => Score(9.9),
        [0, 0, 0, 0, 1, 0] | [0, 0, 1, 0, 0, 0] | [1, 0, 0, 0, 0, 0] => Score(9.8),
        [0, 1, 0, 0, 0, 1] => Score(9.7),
        [0, 0, 0, 1, 0, 1] => Score(9.6),
        [0, 0, 0, 0, 1, 1]
        | [0, 0, 0, 0, 2, 0]
        | [0, 0, 1, 0, 0, 1]
        | [0, 0, 1, 0, 1, 0]
        | [0, 1, 0, 0, 1, 0]
        | [0, 1, 0, 1, 0, 0]
        | [0, 1, 1, 0, 0, 0]
        | [1, 0, 0, 0, 0, 1]
        | [1, 1, 0, 0, 0, 0] => Score(9.5),
        [1, 0, 0, 0, 1, 0] | [1, 0, 0, 1, 0, 0] | [1, 0, 1, 0, 0, 0] => Score(9.4),
        [0, 0, 0, 1, 1, 0]
        | [0, 0, 0, 2, 0, 0]
        | [0, 0, 1, 1, 0, 0]
        | [0, 1, 1, 0, 0, 1]
        | [2, 0, 0, 0, 0, 0] => Score(9.3),
        [0, 0, 0, 0, 2, 1]
        | [0, 0, 1, 0, 1, 1]
        | [0, 0, 1, 1, 0, 1]
        | [0, 0, 2, 0, 0, 1]
        | [0, 1, 0, 0, 1, 1]
        | [0, 1, 0, 0, 2, 0]
        | [0, 1, 0, 2, 0, 0]
        | [0, 1, 1, 0, 1, 0]
        | [0, 1, 1, 1, 0, 0] => Score(9.2),
        [0, 0, 0, 1, 2, 0] | [0, 1, 0, 1, 0, 1] | [1, 0, 0, 0, 2, 0] => Score(9.1),
        [0, 0, 0, 2, 0, 1]
        | [0, 0, 1, 0, 2, 0]
        | [0, 1, 0, 1, 1, 0]
        | [1, 1, 0, 0, 0, 1]
        | [1, 1, 0, 1, 0, 0] => Score(9.0),
        [0, 0, 0, 2, 1, 0]
        | [0, 0, 1, 1, 1, 0]
        | [1, 0, 0, 1, 0, 1]
        | [1, 0, 1, 0, 0, 1]
        | [1, 1, 1, 0, 0, 0] => Score(8.9),
        [0, 0, 1, 2, 0, 0] | [1, 0, 1, 0, 1, 0] | [1, 1, 0, 0, 1, 0] | [2, 1, 0, 0, 0, 0] => {
            Score(8.8)
        }
        [0, 0, 0, 1, 1, 1] | [1, 0, 0, 0, 1, 1] | [1, 0, 0, 2, 0, 0] | [2, 0, 0, 0, 0, 1] => {
            Score(8.7)
        }
        [0, 1, 2, 0, 0, 1]
        | [1, 0, 0, 1, 1, 0]
        | [1, 0, 1, 1, 0, 0]
        | [2, 0, 0, 0, 1, 0]
        | [2, 0, 0, 1, 0, 0] => Score(8.6),
        [0, 1, 0, 0, 2, 1] | [0, 1, 1, 0, 1, 1] | [0, 1, 1, 0, 2, 0] | [2, 0, 1, 0, 0, 0] => {
            Score(8.5)
        }
        [0, 0, 1, 0, 2, 1] | [0, 1, 0, 1, 2, 0] | [0, 1, 1, 2, 0, 0] => Score(8.4),
        [0, 1, 0, 1, 1, 1] | [1, 0, 2, 0, 0, 1] => Score(8.3),
        [0, 0, 2, 0, 1, 1] | [0, 1, 0, 2, 1, 0] | [0, 1, 1, 1, 0, 1] => Score(8.2),
        [0, 0, 0, 1, 2, 1]
        | [0, 0, 0, 2, 2, 0]
        | [0, 0, 1, 1, 1, 1]
        | [0, 0, 1, 1, 2, 0]
        | [0, 1, 0, 2, 0, 1]
        | [1, 0, 0, 0, 2, 1] => Score(8.1),
        [0, 0, 0, 2, 1, 1] | [0, 0, 1, 2, 0, 1] | [0, 1, 1, 1, 1, 0] => Score(8.0),
        [0, 0, 2, 1, 0, 1] => Score(7.9),
        [0, 0, 1, 2, 1, 0] | [1, 1, 1, 0, 0, 1] => Score(7.8),
        [1, 0, 0, 1, 2, 0] | [1, 0, 1, 0, 1, 1] | [1, 1, 0, 1, 0, 1] | [1, 1, 0, 2, 0, 0] => {
            Score(7.7)
        }
        [1, 0, 1, 0, 2, 0]
        | [1, 0, 1, 1, 0, 1]
        | [1, 1, 0, 0, 1, 1]
        | [1, 1, 0, 0, 2, 0]
        | [1, 1, 1, 0, 1, 0] => Score(7.6),
        [0, 1, 2, 0, 1, 1]
        | [1, 0, 0, 2, 0, 1]
        | [1, 1, 0, 1, 1, 0]
        | [2, 0, 0, 0, 2, 0]
        | [2, 0, 1, 0, 0, 1]
        | [2, 1, 0, 0, 0, 1]
        | [2, 1, 1, 0, 0, 0] => Score(7.5),
        [1, 0, 0, 1, 1, 1]
        | [1, 0, 0, 2, 1, 0]
        | [1, 0, 1, 1, 1, 0]
        | [1, 1, 1, 1, 0, 0]
        | [2, 0, 0, 1, 0, 1]
        | [2, 0, 0, 1, 1, 0]
        | [2, 0, 1, 0, 1, 0] => Score(7.4),
        [0, 1, 1, 0, 2, 1] | [2, 1, 0, 0, 1, 0] | [2, 1, 0, 1, 0, 0] => Score(7.3),
        [0, 0, 2, 0, 2, 1]
        | [0, 1, 0, 2, 2, 0]
        | [0, 1, 1, 1, 1, 1]
        | [1, 0, 1, 2, 0, 0]
        | [2, 0, 0, 0, 1, 1]
        | [2, 0, 1, 1, 0, 0] => Score(7.2),
        [0, 1, 0, 1, 2, 1]
        | [0, 1, 0, 2, 1, 1]
        | [0, 1, 1, 2, 1, 0]
        | [0, 1, 2, 1, 0, 1]
        | [1, 1, 2, 0, 0, 1] => Score(7.1),
        [0, 0, 1, 2, 1, 1]
        | [0, 1, 1, 1, 2, 0]
        | [0, 1, 1, 2, 0, 1]
        | [1, 0, 2, 0, 1, 1]
        | [1, 1, 0, 0, 2, 1]
        | [2, 0, 0, 2, 0, 0] => Score(7.0),
        [0, 0, 1, 2, 2, 0] | [0, 0, 2, 1, 1, 1] | [0, 0, 2, 2, 0, 1] => Score(6.9),
        [0, 0, 0, 2, 2, 1] | [1, 1, 0, 2, 1, 0] => Score(6.8),
        [1, 0, 1, 0, 2, 1] | [1, 1, 1, 0, 1, 1] => Score(6.7),
        [1, 1, 0, 2, 0, 1] => Score(6.6),
        [0, 0, 1, 1, 2, 1] | [1, 0, 2, 1, 0, 1] => Score(6.5),
        [1, 0, 0, 1, 2, 1] | [2, 0, 2, 0, 0, 1] => Score(6.4),
        [0, 1, 2, 2, 0, 1] | [1, 0, 0, 2, 1, 1] | [1, 0, 0, 2, 2, 0] => Score(6.3),
        [1, 1, 0, 1, 1, 1] | [1, 1, 1, 0, 2, 0] | [2, 0, 1, 0, 2, 0] => Score(6.2),
        [1, 1, 0, 1, 2, 0] | [1, 1, 1, 2, 0, 0] | [2, 0, 0, 1, 1, 1] | [2, 1, 1, 1, 0, 0] => {
            Score(6.1)
        }
        [2, 1, 0, 0, 2, 0] => Score(6.0),
        [0, 1, 1, 1, 2, 1]
        | [1, 0, 1, 1, 2, 0]
        | [1, 1, 0, 2, 1, 1]
        | [1, 1, 1, 1, 0, 1]
        | [1, 1, 2, 0, 1, 1]
        | [2, 1, 0, 1, 1, 0] => Score(5.9),
        [1, 0, 1, 1, 1, 1]
        | [1, 0, 2, 1, 1, 1]
        | [1, 1, 1, 0, 2, 1]
        | [1, 1, 2, 1, 0, 1]
        | [2, 0, 0, 0, 2, 1]
        | [2, 1, 1, 0, 1, 0] => Score(5.8),
        [1, 0, 1, 2, 0, 1]
        | [1, 0, 1, 2, 1, 0]
        | [1, 1, 1, 1, 1, 0]
        | [1, 1, 1, 1, 1, 1]
        | [1, 1, 1, 2, 1, 0]
        | [2, 0, 1, 1, 0, 1] => Score(5.7),
        [2, 0, 0, 1, 2, 0] => Score(5.6),
        [0, 0, 2, 2, 1, 1]
        | [2, 0, 1, 0, 1, 1]
        | [2, 0, 1, 1, 1, 0]
        | [2, 1, 0, 1, 0, 1]
        | [2, 1, 1, 0, 0, 1] => Score(5.5),
        [1, 0, 2, 0, 2, 1] | [2, 0, 0, 2, 0, 1] | [2, 1, 0, 2, 0, 0] => Score(5.4),
        [0, 1, 0, 2, 2, 1]
        | [1, 0, 2, 2, 0, 1]
        | [1, 1, 0, 1, 2, 1]
        | [2, 0, 1, 2, 0, 0]
        | [2, 1, 0, 0, 1, 1]
        | [2, 1, 2, 0, 0, 1] => Score(5.3),
        [0, 1, 1, 2, 1, 1]
        | [0, 1, 2, 0, 2, 1]
        | [0, 1, 2, 1, 1, 1]
        | [1, 0, 1, 2, 1, 1]
        | [1, 0, 1, 2, 2, 0]
        | [1, 1, 0, 2, 2, 0]
        | [1, 1, 1, 2, 0, 1]
        | [2, 0, 0, 2, 1, 0] => Score(5.2),
        [2, 0, 1, 0, 2, 1] | [2, 0, 2, 0, 1, 1] | [2, 1, 1, 1, 0, 1] => Score(5.1),
        [0, 0, 2, 1, 2, 1] | [0, 1, 1, 2, 2, 0] | [1, 0, 1, 1, 2, 1] | [2, 1, 0, 0, 2, 1] => {
            Score(5.0)
        }
        [1, 0, 0, 2, 2, 1] => Score(4.9),
        [0, 0, 1, 2, 2, 1] | [2, 1, 1, 1, 1, 0] => Score(4.8),
        [1, 1, 1, 1, 2, 0] | [2, 0, 2, 1, 0, 1] => Score(4.7),
        [2, 0, 1, 1, 2, 0] | [2, 1, 1, 2, 0, 0] => Score(4.6),
        [2, 1, 0, 2, 1, 0] | [2, 1, 1, 0, 1, 1] => Score(4.5),
        [2, 1, 0, 2, 0, 1] => Score(4.3),
        [2, 0, 1, 1, 1, 1] | [2, 1, 0, 1, 2, 0] => Score(4.1),
        [2, 0, 0, 2, 1, 1] | [2, 0, 0, 2, 2, 0] | [2, 1, 0, 1, 1, 1] | [2, 1, 1, 0, 2, 0] => {
            Score(4.0)
        }
        [2, 0, 1, 2, 0, 1] => Score(3.6),
        [2, 0, 0, 1, 2, 1] | [2, 0, 1, 2, 1, 0] => Score(3.4),
        [0, 1, 1, 2, 2, 1] | [1, 1, 0, 2, 2, 1] | [1, 1, 2, 0, 2, 1] => Score(3.0),
        [0, 1, 2, 1, 2, 1] | [0, 1, 2, 2, 1, 1] | [1, 1, 1, 2, 1, 1] => Score(2.9),
        [0, 0, 2, 2, 2, 1] => Score(2.7),
        [1, 0, 2, 1, 2, 1] | [1, 1, 2, 1, 1, 1] => Score(2.6),
        [1, 0, 1, 2, 2, 1] => Score(2.5),
        [1, 1, 1, 2, 2, 0] | [2, 0, 2, 2, 0, 1] | [2, 1, 2, 0, 1, 1] | [2, 1, 2, 1, 0, 1] => {
            Score(2.4)
        }
        [1, 1, 1, 1, 2, 1] | [1, 1, 2, 2, 0, 1] => Score(2.3),
        [2, 0, 0, 2, 2, 1] | [2, 1, 0, 2, 1, 1] => Score(2.2),
        [1, 0, 2, 2, 1, 1] | [2, 0, 2, 1, 1, 1] | [2, 1, 1, 0, 2, 1] => Score(2.1),
        [2, 0, 2, 0, 2, 1] | [2, 1, 0, 1, 2, 1] | [2, 1, 0, 2, 2, 0] | [2, 1, 1, 1, 2, 0] => {
            Score(2.0)
        }
        [2, 0, 1, 1, 2, 1] | [2, 0, 1, 2, 1, 1] | [2, 0, 1, 2, 2, 0] => Score(1.9),
        [2, 1, 1, 1, 1, 1] | [2, 1, 1, 2, 0, 1] => Score(1.8),
        [0, 1, 2, 2, 2, 1] | [2, 1, 1, 2, 1, 0] => Score(1.7),
        [1, 1, 1, 2, 2, 1] => Score(1.6),
        [1, 1, 2, 1, 2, 1] => Score(1.5),
        [2, 1, 2, 0, 2, 1] => Score(1.4),
        [1, 0, 2, 2, 2, 1] | [1, 1, 2, 2, 1, 1] => Score(1.3),
        [2, 1, 2, 1, 1, 1] => Score(1.2),
        [2, 0, 2, 1, 2, 1] | [2, 1, 0, 2, 2, 1] => Score(1.1),
        [2, 1, 2, 2, 0, 1] => Score(1.0),
        [2, 0, 2, 2, 1, 1] | [2, 1, 1, 1, 2, 1] => Score(0.9),
        [2, 0, 1, 2, 2, 1] | [2, 1, 1, 2, 2, 0] => Score(0.8),
        [2, 1, 1, 2, 1, 1] => Score(0.7),
        [1, 1, 2, 2, 2, 1] => Score(0.6),
        [2, 1, 2, 1, 2, 1] => Score(0.5),
        [2, 0, 2, 2, 2, 1] => Score(0.4),
        [2, 1, 2, 2, 1, 1] => Score(0.3),
        [2, 1, 1, 2, 2, 1] => Score(0.2),
        [2, 1, 2, 2, 2, 1] => Score(0.1),
        _ => unreachable!(),
    }
}
