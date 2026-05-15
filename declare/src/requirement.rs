use jw_guard_core::enums::{CredentialStrength, LayerHardness};

/// Whether a declared object or mechanism must appear in an observation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum PresenceRequirement {
    /// The item must be present.
    Required,
    /// The item must not be present.
    Forbidden,
    /// The item may be present, but is not required.
    Optional,
}

impl PresenceRequirement {
    /// Returns true when an observed presence satisfies this requirement.
    pub const fn is_satisfied_by(self, present: bool) -> bool {
        match self {
            Self::Required => present,
            Self::Forbidden => !present,
            Self::Optional => true,
        }
    }
}

/// Ordered strength requirement.
///
/// Use this for values where stronger/weaker has a typed order, such as layer
/// hardness or credential strength. Most security declarations should prefer
/// `AtLeast` over `Exactly`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", tag = "kind", content = "value")
)]
pub enum StrengthRequirement<T> {
    /// The observed value must equal the declared value.
    Exactly(T),
    /// The observed value must be greater than or equal to the declared value.
    AtLeast(T),
    /// The observed value must be less than or equal to the declared value.
    AtMost(T),
}

impl<T> StrengthRequirement<T>
where
    T: Copy + Ord,
{
    /// Returns true when an observed value satisfies this requirement.
    pub fn is_satisfied_by(self, observed: T) -> bool {
        match self {
            Self::Exactly(expected) => observed == expected,
            Self::AtLeast(minimum) => observed >= minimum,
            Self::AtMost(maximum) => observed <= maximum,
        }
    }

    /// Returns true when some value in an allowed inclusive range could satisfy
    /// this requirement.
    pub fn is_satisfiable_within(self, minimum: T, maximum: T) -> bool {
        match self {
            Self::Exactly(expected) => expected >= minimum && expected <= maximum,
            Self::AtLeast(required_minimum) => maximum >= required_minimum,
            Self::AtMost(required_maximum) => minimum <= required_maximum,
        }
    }
}

/// Set membership requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "kebab-case", tag = "kind", content = "items")
)]
pub enum SetRequirement<T> {
    /// The observed set must contain every declared item.
    Includes(alloc::vec::Vec<T>),
    /// The observed set must contain none of the declared items.
    Excludes(alloc::vec::Vec<T>),
    /// The observed set must equal the declared set, ignoring order.
    Equals(alloc::vec::Vec<T>),
}

impl<T> SetRequirement<T>
where
    T: Eq,
{
    /// Returns true when observed items satisfy this set requirement.
    pub fn is_satisfied_by(&self, observed: &[T]) -> bool {
        match self {
            Self::Includes(required) => required.iter().all(|item| observed.contains(item)),
            Self::Excludes(forbidden) => forbidden.iter().all(|item| !observed.contains(item)),
            Self::Equals(expected) => {
                expected.len() == observed.len()
                    && expected.iter().all(|item| observed.contains(item))
                    && observed.iter().all(|item| expected.contains(item))
            }
        }
    }
}

/// Requirement alias for boundary protection hardness.
pub type HardnessRequirement = StrengthRequirement<LayerHardness>;

/// Requirement alias for identity activation credential strength.
pub type CredentialRequirement = StrengthRequirement<CredentialStrength>;

#[cfg(test)]
mod tests {
    use jw_guard_core::enums::LayerHardness;

    use super::StrengthRequirement;

    #[test]
    fn strength_requirements_are_ordered_requirements() {
        assert!(StrengthRequirement::AtLeast(LayerHardness::H3).is_satisfied_by(LayerHardness::H4));
        assert!(!StrengthRequirement::AtLeast(LayerHardness::H4).is_satisfied_by(LayerHardness::H3));
        assert!(StrengthRequirement::Exactly(LayerHardness::H3)
            .is_satisfiable_within(LayerHardness::H2, LayerHardness::H4));
    }
}
