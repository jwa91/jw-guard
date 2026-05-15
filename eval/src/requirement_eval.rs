use jw_guard_core::{RequirementDeclaration, RequirementOperator, RequirementValue};

use crate::{Membership, MembershipSelection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequirementOutcome {
    Satisfied,
    Violated,
    Unknown,
    OperatorValueMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequirementReasonTag {
    OperatorValueMismatch,
    PresenceSatisfied,
    PresenceViolated,
    CountSatisfied,
    CountViolated,
    MembershipUnknown,
    UnsupportedOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequirementEvaluation {
    outcome: RequirementOutcome,
    reason: RequirementReasonTag,
}

impl RequirementEvaluation {
    #[must_use]
    pub const fn new(outcome: RequirementOutcome, reason: RequirementReasonTag) -> Self {
        Self { outcome, reason }
    }

    #[must_use]
    pub const fn outcome(self) -> RequirementOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn reason(self) -> RequirementReasonTag {
        self.reason
    }
}

#[must_use]
pub fn evaluate_requirement(
    requirement: &RequirementDeclaration,
    membership_selection: &[MembershipSelection],
) -> RequirementEvaluation {
    if !operator_value_compatible(requirement.operator, &requirement.value) {
        return RequirementEvaluation::new(
            RequirementOutcome::OperatorValueMismatch,
            RequirementReasonTag::OperatorValueMismatch,
        );
    }

    let tally = MembershipTally::from_selection(membership_selection);

    match requirement.operator {
        RequirementOperator::PresenceRequired => evaluate_presence_required(&tally),
        RequirementOperator::PresenceForbidden => evaluate_presence_forbidden(&tally),
        RequirementOperator::PresenceOptional => RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::PresenceSatisfied,
        ),
        RequirementOperator::CountEqual => {
            let RequirementValue::U64(target) = requirement.value else {
                return RequirementEvaluation::new(
                    RequirementOutcome::OperatorValueMismatch,
                    RequirementReasonTag::OperatorValueMismatch,
                );
            };
            evaluate_count_equal(target, &tally)
        }
        RequirementOperator::CountMin => {
            let RequirementValue::U64(target) = requirement.value else {
                return RequirementEvaluation::new(
                    RequirementOutcome::OperatorValueMismatch,
                    RequirementReasonTag::OperatorValueMismatch,
                );
            };
            evaluate_count_min(target, &tally)
        }
        RequirementOperator::CountMax => {
            let RequirementValue::U64(target) = requirement.value else {
                return RequirementEvaluation::new(
                    RequirementOutcome::OperatorValueMismatch,
                    RequirementReasonTag::OperatorValueMismatch,
                );
            };
            evaluate_count_max(target, &tally)
        }
        RequirementOperator::SetIncludes
        | RequirementOperator::SetExcludes
        | RequirementOperator::SetEquals
        | RequirementOperator::TemporalBefore
        | RequirementOperator::TemporalAfter
        | RequirementOperator::TemporalWithin
        | RequirementOperator::RelationExists
        | RequirementOperator::RelationNotExists
        | RequirementOperator::RelationPathLengthMax
        | RequirementOperator::RelationEdgeCountMax => RequirementEvaluation::new(
            RequirementOutcome::Unknown,
            RequirementReasonTag::UnsupportedOperator,
        ),
    }
}

#[must_use]
pub fn operator_value_compatible(operator: RequirementOperator, value: &RequirementValue) -> bool {
    match operator {
        RequirementOperator::PresenceRequired
        | RequirementOperator::PresenceForbidden
        | RequirementOperator::PresenceOptional => matches!(value, RequirementValue::Bool(_)),
        RequirementOperator::CountEqual
        | RequirementOperator::CountMin
        | RequirementOperator::CountMax
        | RequirementOperator::RelationPathLengthMax
        | RequirementOperator::RelationEdgeCountMax => matches!(value, RequirementValue::U64(_)),
        RequirementOperator::SetIncludes
        | RequirementOperator::SetExcludes
        | RequirementOperator::SetEquals => {
            matches!(value, RequirementValue::Names(_))
        }
        RequirementOperator::TemporalBefore
        | RequirementOperator::TemporalAfter
        | RequirementOperator::TemporalWithin => {
            matches!(value, RequirementValue::DurationSeconds(_))
        }
        RequirementOperator::RelationExists | RequirementOperator::RelationNotExists => {
            matches!(value, RequirementValue::Bool(_))
        }
    }
}

fn evaluate_presence_required(tally: &MembershipTally) -> RequirementEvaluation {
    if tally.member_count > 0 {
        RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::PresenceSatisfied,
        )
    } else if tally.unknown_count > 0 {
        RequirementEvaluation::new(
            RequirementOutcome::Unknown,
            RequirementReasonTag::MembershipUnknown,
        )
    } else {
        RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::PresenceViolated,
        )
    }
}

fn evaluate_presence_forbidden(tally: &MembershipTally) -> RequirementEvaluation {
    if tally.member_count > 0 {
        RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::PresenceViolated,
        )
    } else if tally.unknown_count > 0 {
        RequirementEvaluation::new(
            RequirementOutcome::Unknown,
            RequirementReasonTag::MembershipUnknown,
        )
    } else {
        RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::PresenceSatisfied,
        )
    }
}

fn evaluate_count_equal(target: u64, tally: &MembershipTally) -> RequirementEvaluation {
    let min_possible = tally.member_count;
    let max_possible = tally.member_count + tally.unknown_count;

    if target < min_possible || target > max_possible {
        return RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::CountViolated,
        );
    }

    if tally.unknown_count > 0 {
        return RequirementEvaluation::new(
            RequirementOutcome::Unknown,
            RequirementReasonTag::MembershipUnknown,
        );
    }

    if tally.member_count == target {
        RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::CountSatisfied,
        )
    } else {
        RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::CountViolated,
        )
    }
}

fn evaluate_count_min(target: u64, tally: &MembershipTally) -> RequirementEvaluation {
    if tally.member_count >= target {
        return RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::CountSatisfied,
        );
    }

    if tally.member_count + tally.unknown_count < target {
        return RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::CountViolated,
        );
    }

    RequirementEvaluation::new(
        RequirementOutcome::Unknown,
        RequirementReasonTag::MembershipUnknown,
    )
}

fn evaluate_count_max(target: u64, tally: &MembershipTally) -> RequirementEvaluation {
    if tally.member_count > target {
        return RequirementEvaluation::new(
            RequirementOutcome::Violated,
            RequirementReasonTag::CountViolated,
        );
    }

    if tally.member_count + tally.unknown_count <= target {
        return RequirementEvaluation::new(
            RequirementOutcome::Satisfied,
            RequirementReasonTag::CountSatisfied,
        );
    }

    RequirementEvaluation::new(
        RequirementOutcome::Unknown,
        RequirementReasonTag::MembershipUnknown,
    )
}

#[derive(Debug, Clone, Copy)]
struct MembershipTally {
    member_count: u64,
    unknown_count: u64,
}

impl MembershipTally {
    fn from_selection(selection: &[MembershipSelection]) -> Self {
        let mut member_count = 0_u64;
        let mut unknown_count = 0_u64;

        for item in selection {
            match item.membership() {
                Membership::Member => member_count += 1,
                Membership::NonMember => {}
                Membership::Unknown => unknown_count += 1,
            }
        }

        Self {
            member_count,
            unknown_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{evaluate_requirement, RequirementOutcome};
    use crate::{Membership, MembershipSelection};
    use jw_guard_core::{
        ReferentId, RequirementDeclaration, RequirementId, RequirementOperator, RequirementSortId,
        RequirementValue,
    };

    fn id16(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn requirement(
        operator: RequirementOperator,
        value: RequirementValue,
    ) -> RequirementDeclaration {
        RequirementDeclaration {
            id: RequirementId::from_bytes(id16(40)),
            sort: RequirementSortId(2),
            operator,
            value,
        }
    }

    #[test]
    fn count_min_propagates_unknown_when_threshold_depends_on_missing_membership() {
        let requirement = requirement(RequirementOperator::CountMin, RequirementValue::U64(2));
        let selection = vec![
            MembershipSelection::new(ReferentId::from_bytes(id16(1)), Membership::Member),
            MembershipSelection::new(ReferentId::from_bytes(id16(2)), Membership::Unknown),
        ];

        let evaluation = evaluate_requirement(&requirement, &selection);

        assert_eq!(evaluation.outcome(), RequirementOutcome::Unknown);
    }

    #[test]
    fn count_min_violates_when_known_and_unknown_cannot_reach_threshold() {
        let requirement = requirement(RequirementOperator::CountMin, RequirementValue::U64(3));
        let selection = vec![
            MembershipSelection::new(ReferentId::from_bytes(id16(1)), Membership::Member),
            MembershipSelection::new(ReferentId::from_bytes(id16(2)), Membership::Unknown),
        ];

        let evaluation = evaluate_requirement(&requirement, &selection);

        assert_eq!(evaluation.outcome(), RequirementOutcome::Violated);
    }

    #[test]
    fn operator_value_mismatch_is_explicit() {
        let requirement = requirement(RequirementOperator::CountMin, RequirementValue::Bool(true));
        let selection = vec![MembershipSelection::new(
            ReferentId::from_bytes(id16(1)),
            Membership::Member,
        )];

        let evaluation = evaluate_requirement(&requirement, &selection);

        assert_eq!(
            evaluation.outcome(),
            RequirementOutcome::OperatorValueMismatch
        );
    }
}
