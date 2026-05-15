use alloc::vec::Vec;

use jw_guard_core::{DeclaredModel, PolicyDeclaration, PolicyId};

use crate::{
    evaluate_membership_for_carrier, evaluate_requirement, Carrier, Membership,
    MembershipSelection, ReferentContext, RequirementOutcome, RequirementReasonTag,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionOutcome {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
    OperatorValueMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionReasonTag {
    ScopeMissing,
    RequirementMissing,
    RequirementSatisfied,
    RequirementViolated,
    MembershipUnknown,
    UnsupportedOperator,
    OperatorValueMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision {
    policy_id: PolicyId,
    outcome: DecisionOutcome,
    reason: DecisionReasonTag,
}

impl Decision {
    #[must_use]
    pub const fn new(
        policy_id: PolicyId,
        outcome: DecisionOutcome,
        reason: DecisionReasonTag,
    ) -> Self {
        Self {
            policy_id,
            outcome,
            reason,
        }
    }

    #[must_use]
    pub const fn policy_id(&self) -> PolicyId {
        self.policy_id
    }

    #[must_use]
    pub const fn outcome(&self) -> DecisionOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn reason(&self) -> DecisionReasonTag {
        self.reason
    }
}

#[must_use]
pub fn evaluate_policy(
    model: &DeclaredModel,
    policy: &PolicyDeclaration,
    referent_contexts: &[ReferentContext<'_>],
) -> Decision {
    let Some(scope) = model.scopes.iter().find(|scope| scope.id == policy.scope) else {
        return Decision::new(
            policy.id,
            DecisionOutcome::NotApplicable,
            DecisionReasonTag::ScopeMissing,
        );
    };

    let Some(requirement) = model
        .requirements
        .iter()
        .find(|requirement| requirement.id == policy.requirement)
    else {
        return Decision::new(
            policy.id,
            DecisionOutcome::NotApplicable,
            DecisionReasonTag::RequirementMissing,
        );
    };

    let carrier = Carrier::from_declared_model(model, scope.referent_sort);
    let membership_selection: Vec<MembershipSelection> = evaluate_membership_for_carrier(
        &scope.predicate,
        carrier.referent_ids(),
        referent_contexts,
    );

    let has_unknown_membership = membership_selection
        .iter()
        .any(|selection| selection.membership() == Membership::Unknown);

    let requirement_evaluation = evaluate_requirement(requirement, &membership_selection);
    match requirement_evaluation.outcome() {
        RequirementOutcome::Satisfied => Decision::new(
            policy.id,
            DecisionOutcome::Satisfied,
            DecisionReasonTag::RequirementSatisfied,
        ),
        RequirementOutcome::Violated => Decision::new(
            policy.id,
            DecisionOutcome::Violated,
            DecisionReasonTag::RequirementViolated,
        ),
        RequirementOutcome::OperatorValueMismatch => Decision::new(
            policy.id,
            DecisionOutcome::OperatorValueMismatch,
            DecisionReasonTag::OperatorValueMismatch,
        ),
        RequirementOutcome::Unknown => match requirement_evaluation.reason() {
            RequirementReasonTag::UnsupportedOperator => Decision::new(
                policy.id,
                DecisionOutcome::Unknown,
                DecisionReasonTag::UnsupportedOperator,
            ),
            RequirementReasonTag::MembershipUnknown if has_unknown_membership => Decision::new(
                policy.id,
                DecisionOutcome::Unknown,
                DecisionReasonTag::MembershipUnknown,
            ),
            _ => Decision::new(
                policy.id,
                DecisionOutcome::Unknown,
                DecisionReasonTag::MembershipUnknown,
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::{evaluate_policy, DecisionOutcome, DecisionReasonTag};
    use crate::ReferentContext;
    use jw_guard_core::{
        ActorDeclaration, ActorId, CanonicalName, CanonicalPaths, DeclaredModel, EvaluationContext,
        MembershipPredicate, ModelDeclaration, ModelId, PolicyDeclaration, PolicyId,
        ReferentDeclaration, ReferentId, ReferentSortId, RequirementDeclaration, RequirementId,
        RequirementOperator, RequirementSortId, RequirementValue, ScopeId, SemVer, Timestamp,
        TypedScopeDeclaration,
    };

    fn id16(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn build_model(
        requirement: RequirementDeclaration,
    ) -> (DeclaredModel, PolicyDeclaration, ReferentId) {
        let actor = ActorDeclaration {
            id: ActorId::from_bytes(id16(2)),
            role: CanonicalName::new("owner".to_string()).expect("valid role"),
        };
        let referent = ReferentDeclaration {
            id: ReferentId::from_bytes(id16(3)),
            sort: ReferentSortId(1),
        };
        let referent_id = referent.id;
        let scope = TypedScopeDeclaration::new(
            ScopeId::from_bytes(id16(4)),
            ReferentSortId(1),
            EvaluationContext {
                model_version: SemVer::new(0, 1, 0),
                snapshot: Timestamp::from_unix_seconds(1),
                namespace: CanonicalName::new("default".to_string()).expect("valid namespace"),
                mapper_version: SemVer::new(0, 1, 0),
            },
            MembershipPredicate::HasTag(
                CanonicalName::new("tier1".to_string()).expect("valid tag"),
            ),
        );
        let policy = PolicyDeclaration::new(
            PolicyId::from_bytes(id16(5)),
            actor.id,
            scope.id,
            requirement.id,
        );

        let model = DeclaredModel {
            model: ModelDeclaration {
                id: ModelId::from_bytes(id16(1)),
                version: SemVer::new(0, 1, 0),
                declared_at: Timestamp::from_unix_seconds(1),
                declared_by: actor.id,
            },
            actors: vec![actor],
            referents: vec![referent],
            boundaries: vec![],
            edges: vec![],
            scopes: vec![scope],
            requirements: vec![requirement],
            policies: vec![policy.clone()],
            canonical_paths: CanonicalPaths {
                model: "model/root".to_string(),
                actors: vec!["actor/owner".to_string()],
                referents: vec!["referent/service".to_string()],
                boundaries: vec![],
                edges: vec![],
                scopes: vec!["scope/default".to_string()],
                requirements: vec!["requirement/default".to_string()],
                policies: vec!["policy/default".to_string()],
            },
        };

        (model, policy, referent_id)
    }

    #[test]
    fn evaluate_policy_propagates_unknown_when_context_is_missing() {
        let requirement = RequirementDeclaration {
            id: RequirementId::from_bytes(id16(10)),
            sort: RequirementSortId(1),
            operator: RequirementOperator::CountMin,
            value: RequirementValue::U64(1),
        };
        let (model, policy, _) = build_model(requirement);

        let decision = evaluate_policy(&model, &policy, &[]);

        assert_eq!(decision.outcome(), DecisionOutcome::Unknown);
        assert_eq!(decision.reason(), DecisionReasonTag::MembershipUnknown);
    }

    #[test]
    fn evaluate_policy_returns_satisfied_when_predicate_matches_and_requirement_holds() {
        let requirement = RequirementDeclaration {
            id: RequirementId::from_bytes(id16(11)),
            sort: RequirementSortId(1),
            operator: RequirementOperator::CountMin,
            value: RequirementValue::U64(1),
        };
        let (model, policy, referent_id) = build_model(requirement);
        let tag = CanonicalName::new("tier1".to_string()).expect("valid tag");
        let tags = vec![tag];
        let contexts = vec![ReferentContext::new(
            referent_id,
            None,
            Some(tags.as_slice()),
            None,
        )];

        let decision = evaluate_policy(&model, &policy, contexts.as_slice());

        assert_eq!(decision.outcome(), DecisionOutcome::Satisfied);
        assert_eq!(decision.reason(), DecisionReasonTag::RequirementSatisfied);
    }

    #[test]
    fn evaluate_policy_distinguishes_operator_value_mismatch_from_violation() {
        let mismatch_requirement = RequirementDeclaration {
            id: RequirementId::from_bytes(id16(12)),
            sort: RequirementSortId(1),
            operator: RequirementOperator::CountMin,
            value: RequirementValue::Bool(true),
        };
        let (mismatch_model, mismatch_policy, _) = build_model(mismatch_requirement);
        let mismatch_decision = evaluate_policy(&mismatch_model, &mismatch_policy, &[]);
        assert_eq!(
            mismatch_decision.outcome(),
            DecisionOutcome::OperatorValueMismatch
        );

        let violated_requirement = RequirementDeclaration {
            id: RequirementId::from_bytes(id16(13)),
            sort: RequirementSortId(1),
            operator: RequirementOperator::CountMin,
            value: RequirementValue::U64(2),
        };
        let (violated_model, violated_policy, referent_id) = build_model(violated_requirement);
        let tag = CanonicalName::new("tier1".to_string()).expect("valid tag");
        let tags = vec![tag];
        let contexts = vec![ReferentContext::new(
            referent_id,
            None,
            Some(tags.as_slice()),
            None,
        )];
        let violated_decision =
            evaluate_policy(&violated_model, &violated_policy, contexts.as_slice());
        assert_eq!(violated_decision.outcome(), DecisionOutcome::Violated);
        assert_eq!(
            violated_decision.reason(),
            DecisionReasonTag::RequirementViolated
        );
    }
}
