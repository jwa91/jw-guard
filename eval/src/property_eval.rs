use jw_guard_core::CanonicalName;
use jw_guard_mapper::{MappedEvidence, MappedPropertyClaim, MappedValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyOutcome {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
    ValueTypeMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropertyReasonTag {
    PropertySatisfied,
    PropertyViolated,
    PropertyMissing,
    SubjectMissing,
    ValueTypeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyRequirement {
    subject: CanonicalName,
    property: CanonicalName,
    expected: MappedValue,
}

impl PropertyRequirement {
    #[must_use]
    pub const fn new(
        subject: CanonicalName,
        property: CanonicalName,
        expected: MappedValue,
    ) -> Self {
        Self {
            subject,
            property,
            expected,
        }
    }

    #[must_use]
    pub const fn subject(&self) -> &CanonicalName {
        &self.subject
    }

    #[must_use]
    pub const fn property(&self) -> &CanonicalName {
        &self.property
    }

    #[must_use]
    pub const fn expected(&self) -> &MappedValue {
        &self.expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PropertyEvaluation {
    outcome: PropertyOutcome,
    reason: PropertyReasonTag,
}

impl PropertyEvaluation {
    #[must_use]
    pub const fn new(outcome: PropertyOutcome, reason: PropertyReasonTag) -> Self {
        Self { outcome, reason }
    }

    #[must_use]
    pub const fn outcome(self) -> PropertyOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn reason(self) -> PropertyReasonTag {
        self.reason
    }
}

#[must_use]
pub fn evaluate_property_requirement(
    requirement: &PropertyRequirement,
    evidence: &MappedEvidence,
) -> PropertyEvaluation {
    if !evidence
        .referents()
        .iter()
        .any(|referent| &referent.name == requirement.subject())
    {
        return PropertyEvaluation::new(
            PropertyOutcome::NotApplicable,
            PropertyReasonTag::SubjectMissing,
        );
    }

    let Some(claim) = find_property_claim(evidence, requirement.subject(), requirement.property())
    else {
        return PropertyEvaluation::new(
            PropertyOutcome::Unknown,
            PropertyReasonTag::PropertyMissing,
        );
    };

    if !mapped_value_same_type(&claim.value, requirement.expected()) {
        return PropertyEvaluation::new(
            PropertyOutcome::ValueTypeMismatch,
            PropertyReasonTag::ValueTypeMismatch,
        );
    }

    if &claim.value == requirement.expected() {
        PropertyEvaluation::new(
            PropertyOutcome::Satisfied,
            PropertyReasonTag::PropertySatisfied,
        )
    } else {
        PropertyEvaluation::new(
            PropertyOutcome::Violated,
            PropertyReasonTag::PropertyViolated,
        )
    }
}

fn find_property_claim<'a>(
    evidence: &'a MappedEvidence,
    subject: &CanonicalName,
    property: &CanonicalName,
) -> Option<&'a MappedPropertyClaim> {
    evidence
        .property_claims()
        .iter()
        .find(|claim| &claim.subject == subject && &claim.property == property)
}

fn mapped_value_same_type(left: &MappedValue, right: &MappedValue) -> bool {
    matches!(
        (left, right),
        (MappedValue::Bool(_), MappedValue::Bool(_))
            | (MappedValue::U64(_), MappedValue::U64(_))
            | (MappedValue::Name(_), MappedValue::Name(_))
            | (MappedValue::Names(_), MappedValue::Names(_))
            | (
                MappedValue::DurationSeconds(_),
                MappedValue::DurationSeconds(_)
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use jw_guard_core::{SemVer, Timestamp};
    use jw_guard_mapper::{MappedReferent, MappedSource, MapperIdentity};

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

    fn evidence_with_property(value: MappedValue) -> MappedEvidence {
        MappedEvidence::new(
            source(),
            vec![MappedReferent::new(name("web"), name("service"))],
            vec![MappedPropertyClaim::new(
                name("web"),
                name("privileged"),
                value,
                Timestamp::from_unix_seconds(1),
            )],
        )
        .expect("mapped evidence should be valid")
    }

    fn privileged_requirement(expected: MappedValue) -> PropertyRequirement {
        PropertyRequirement::new(name("web"), name("privileged"), expected)
    }

    #[test]
    fn property_requirement_is_satisfied_when_observed_value_matches() {
        let evidence = evidence_with_property(MappedValue::Bool(false));
        let requirement = privileged_requirement(MappedValue::Bool(false));

        let evaluation = evaluate_property_requirement(&requirement, &evidence);

        assert_eq!(evaluation.outcome(), PropertyOutcome::Satisfied);
        assert_eq!(evaluation.reason(), PropertyReasonTag::PropertySatisfied);
    }

    #[test]
    fn property_requirement_is_violated_when_observed_value_differs() {
        let evidence = evidence_with_property(MappedValue::Bool(true));
        let requirement = privileged_requirement(MappedValue::Bool(false));

        let evaluation = evaluate_property_requirement(&requirement, &evidence);

        assert_eq!(evaluation.outcome(), PropertyOutcome::Violated);
        assert_eq!(evaluation.reason(), PropertyReasonTag::PropertyViolated);
    }

    #[test]
    fn property_requirement_is_unknown_when_claim_is_missing() {
        let evidence = MappedEvidence::new(
            source(),
            vec![MappedReferent::new(name("web"), name("service"))],
            vec![],
        )
        .expect("mapped evidence should be valid");
        let requirement = privileged_requirement(MappedValue::Bool(false));

        let evaluation = evaluate_property_requirement(&requirement, &evidence);

        assert_eq!(evaluation.outcome(), PropertyOutcome::Unknown);
        assert_eq!(evaluation.reason(), PropertyReasonTag::PropertyMissing);
    }

    #[test]
    fn property_requirement_is_not_applicable_when_subject_is_missing() {
        let evidence =
            MappedEvidence::new(source(), vec![], vec![]).expect("mapped evidence should be valid");
        let requirement = privileged_requirement(MappedValue::Bool(false));

        let evaluation = evaluate_property_requirement(&requirement, &evidence);

        assert_eq!(evaluation.outcome(), PropertyOutcome::NotApplicable);
        assert_eq!(evaluation.reason(), PropertyReasonTag::SubjectMissing);
    }

    #[test]
    fn property_requirement_distinguishes_value_type_mismatch() {
        let evidence = evidence_with_property(MappedValue::Bool(false));
        let requirement = privileged_requirement(MappedValue::U64(0));

        let evaluation = evaluate_property_requirement(&requirement, &evidence);

        assert_eq!(evaluation.outcome(), PropertyOutcome::ValueTypeMismatch);
        assert_eq!(evaluation.reason(), PropertyReasonTag::ValueTypeMismatch);
    }
}
