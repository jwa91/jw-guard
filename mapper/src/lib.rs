#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use jw_guard_core::{CanonicalName, SemVer, Timestamp};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapperIdentity {
    pub name: CanonicalName,
    pub version: SemVer,
}

impl MapperIdentity {
    #[must_use]
    pub const fn new(name: CanonicalName, version: SemVer) -> Self {
        Self { name, version }
    }
}

pub trait Mapper {
    type Input: ?Sized;

    fn identity(&self) -> MapperIdentity;

    fn map(&self, input: &Self::Input) -> Result<MappedEvidence, MapError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedEvidence {
    source: MappedSource,
    referents: Vec<MappedReferent>,
    property_claims: Vec<MappedPropertyClaim>,
}

impl MappedEvidence {
    pub fn new(
        source: MappedSource,
        mut referents: Vec<MappedReferent>,
        mut property_claims: Vec<MappedPropertyClaim>,
    ) -> Result<Self, MapError> {
        referents.sort_by(mapped_referent_order);
        property_claims.sort_by(mapped_property_claim_order);

        let mut violations = Vec::new();
        collect_duplicate_referents(&referents, &mut violations);
        collect_duplicate_property_claims(&property_claims, &mut violations);
        collect_claims_for_unknown_referents(&referents, &property_claims, &mut violations);

        if !violations.is_empty() {
            return Err(MapError::InvalidOutput(violations));
        }

        Ok(Self {
            source,
            referents,
            property_claims,
        })
    }

    #[must_use]
    pub const fn source(&self) -> &MappedSource {
        &self.source
    }

    #[must_use]
    pub fn referents(&self) -> &[MappedReferent] {
        &self.referents
    }

    #[must_use]
    pub fn property_claims(&self) -> &[MappedPropertyClaim] {
        &self.property_claims
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedSource {
    pub mapper: MapperIdentity,
    pub input_kind: CanonicalName,
    pub observed_at: Timestamp,
}

impl MappedSource {
    #[must_use]
    pub const fn new(
        mapper: MapperIdentity,
        input_kind: CanonicalName,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            mapper,
            input_kind,
            observed_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedReferent {
    pub name: CanonicalName,
    pub sort: CanonicalName,
}

impl MappedReferent {
    #[must_use]
    pub const fn new(name: CanonicalName, sort: CanonicalName) -> Self {
        Self { name, sort }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedPropertyClaim {
    pub subject: CanonicalName,
    pub property: CanonicalName,
    pub value: MappedValue,
    pub observed_at: Timestamp,
}

impl MappedPropertyClaim {
    #[must_use]
    pub const fn new(
        subject: CanonicalName,
        property: CanonicalName,
        value: MappedValue,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            subject,
            property,
            value,
            observed_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MappedValue {
    Bool(bool),
    U64(u64),
    Name(CanonicalName),
    Names(Vec<CanonicalName>),
    DurationSeconds(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    InvalidInput(MapErrorCode),
    InvalidOutput(Vec<MapViolation>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapErrorCode {
    UnsupportedInput,
    InvalidInputShape,
    AmbiguousInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapViolation {
    DuplicateReferent(CanonicalName),
    DuplicatePropertyClaim {
        subject: CanonicalName,
        property: CanonicalName,
    },
    PropertyClaimSubjectMissing {
        subject: CanonicalName,
        property: CanonicalName,
    },
}

fn mapped_referent_order(left: &MappedReferent, right: &MappedReferent) -> Ordering {
    left.name
        .cmp(&right.name)
        .then_with(|| left.sort.cmp(&right.sort))
}

fn mapped_property_claim_order(
    left: &MappedPropertyClaim,
    right: &MappedPropertyClaim,
) -> Ordering {
    left.subject
        .cmp(&right.subject)
        .then_with(|| left.property.cmp(&right.property))
        .then_with(|| mapped_value_order(&left.value, &right.value))
}

fn mapped_value_order(left: &MappedValue, right: &MappedValue) -> Ordering {
    mapped_value_discriminant(left)
        .cmp(&mapped_value_discriminant(right))
        .then_with(|| match (left, right) {
            (MappedValue::Bool(left), MappedValue::Bool(right)) => left.cmp(right),
            (MappedValue::U64(left), MappedValue::U64(right)) => left.cmp(right),
            (MappedValue::Name(left), MappedValue::Name(right)) => left.cmp(right),
            (MappedValue::Names(left), MappedValue::Names(right)) => left.cmp(right),
            (MappedValue::DurationSeconds(left), MappedValue::DurationSeconds(right)) => {
                left.cmp(right)
            }
            _ => Ordering::Equal,
        })
}

fn mapped_value_discriminant(value: &MappedValue) -> u8 {
    match value {
        MappedValue::Bool(_) => 0,
        MappedValue::U64(_) => 1,
        MappedValue::Name(_) => 2,
        MappedValue::Names(_) => 3,
        MappedValue::DurationSeconds(_) => 4,
    }
}

fn collect_duplicate_referents(referents: &[MappedReferent], violations: &mut Vec<MapViolation>) {
    for pair in referents.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.name == current.name {
            violations.push(MapViolation::DuplicateReferent(current.name.clone()));
        }
    }
}

fn collect_duplicate_property_claims(
    property_claims: &[MappedPropertyClaim],
    violations: &mut Vec<MapViolation>,
) {
    for pair in property_claims.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        if previous.subject == current.subject && previous.property == current.property {
            violations.push(MapViolation::DuplicatePropertyClaim {
                subject: current.subject.clone(),
                property: current.property.clone(),
            });
        }
    }
}

fn collect_claims_for_unknown_referents(
    referents: &[MappedReferent],
    property_claims: &[MappedPropertyClaim],
    violations: &mut Vec<MapViolation>,
) {
    for claim in property_claims {
        if !referents
            .iter()
            .any(|referent| referent.name == claim.subject)
        {
            violations.push(MapViolation::PropertyClaimSubjectMissing {
                subject: claim.subject.clone(),
                property: claim.property.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn name(value: &str) -> CanonicalName {
        CanonicalName::new(value.to_string()).expect("test name should be canonical")
    }

    fn source() -> MappedSource {
        MappedSource::new(
            MapperIdentity::new(name("docker-compose"), SemVer::new(0, 1, 0)),
            name("docker-compose-yaml"),
            Timestamp::from_unix_seconds(1),
        )
    }

    #[test]
    fn mapped_evidence_sorts_referents_and_property_claims() {
        let evidence = MappedEvidence::new(
            source(),
            vec![
                MappedReferent::new(name("web"), name("service")),
                MappedReferent::new(name("db"), name("service")),
            ],
            vec![
                MappedPropertyClaim::new(
                    name("web"),
                    name("privileged"),
                    MappedValue::Bool(false),
                    Timestamp::from_unix_seconds(1),
                ),
                MappedPropertyClaim::new(
                    name("db"),
                    name("privileged"),
                    MappedValue::Bool(false),
                    Timestamp::from_unix_seconds(1),
                ),
            ],
        )
        .expect("mapped evidence should be valid");

        assert_eq!(evidence.referents()[0].name, name("db"));
        assert_eq!(evidence.property_claims()[0].subject, name("db"));
    }

    #[test]
    fn mapped_evidence_rejects_property_claim_for_unknown_referent() {
        let error = MappedEvidence::new(
            source(),
            vec![MappedReferent::new(name("web"), name("service"))],
            vec![MappedPropertyClaim::new(
                name("db"),
                name("privileged"),
                MappedValue::Bool(false),
                Timestamp::from_unix_seconds(1),
            )],
        )
        .expect_err("unknown referent should fail");

        assert_eq!(
            error,
            MapError::InvalidOutput(vec![MapViolation::PropertyClaimSubjectMissing {
                subject: name("db"),
                property: name("privileged"),
            }])
        );
    }

    #[test]
    fn mapped_evidence_rejects_duplicate_policy_agnostic_property_claims() {
        let error = MappedEvidence::new(
            source(),
            vec![MappedReferent::new(name("web"), name("service"))],
            vec![
                MappedPropertyClaim::new(
                    name("web"),
                    name("privileged"),
                    MappedValue::Bool(false),
                    Timestamp::from_unix_seconds(1),
                ),
                MappedPropertyClaim::new(
                    name("web"),
                    name("privileged"),
                    MappedValue::Bool(true),
                    Timestamp::from_unix_seconds(1),
                ),
            ],
        )
        .expect_err("duplicate property claim should fail");

        assert_eq!(
            error,
            MapError::InvalidOutput(vec![MapViolation::DuplicatePropertyClaim {
                subject: name("web"),
                property: name("privileged"),
            }])
        );
    }
}
