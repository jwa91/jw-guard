use alloc::vec::Vec;

use jw_guard_core::{DeclaredModel, ReferentId, ReferentSortId};

/// Deterministic carrier for one referent sort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carrier {
    referent_sort: ReferentSortId,
    referent_ids: Vec<ReferentId>,
}

impl Carrier {
    #[must_use]
    pub fn from_declared_model(model: &DeclaredModel, referent_sort: ReferentSortId) -> Self {
        let mut referent_ids: Vec<ReferentId> = model
            .referents
            .iter()
            .filter(|referent| referent.sort == referent_sort)
            .map(|referent| referent.id)
            .collect();

        referent_ids.sort_by_key(|referent_id| referent_id.as_bytes());

        Self {
            referent_sort,
            referent_ids,
        }
    }

    #[must_use]
    pub const fn referent_sort(&self) -> ReferentSortId {
        self.referent_sort
    }

    #[must_use]
    pub fn referent_ids(&self) -> &[ReferentId] {
        &self.referent_ids
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::Carrier;
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

    fn model_with_referents(referents: Vec<ReferentDeclaration>) -> DeclaredModel {
        let actor = ActorDeclaration {
            id: ActorId::from_bytes(id16(2)),
            role: CanonicalName::new("owner".to_string()).expect("valid role"),
        };

        let scope = TypedScopeDeclaration::new(
            ScopeId::from_bytes(id16(10)),
            ReferentSortId(1),
            EvaluationContext {
                model_version: SemVer::new(0, 1, 0),
                snapshot: Timestamp::from_unix_seconds(1),
                namespace: CanonicalName::new("default".to_string()).expect("valid namespace"),
                mapper_version: SemVer::new(0, 1, 0),
            },
            MembershipPredicate::All,
        );

        let requirement = RequirementDeclaration::new(
            RequirementId::from_bytes(id16(11)),
            RequirementSortId(1),
            RequirementOperator::CountMin,
            RequirementValue::U64(1),
        )
        .expect("compatible operator/value");

        let policy = PolicyDeclaration::new(
            PolicyId::from_bytes(id16(12)),
            actor.id,
            scope.id,
            requirement.id,
        );

        DeclaredModel {
            model: ModelDeclaration {
                id: ModelId::from_bytes(id16(1)),
                version: SemVer::new(0, 1, 0),
                declared_at: Timestamp::from_unix_seconds(1),
                declared_by: actor.id,
            },
            actors: vec![actor],
            referents,
            boundaries: vec![],
            edges: vec![],
            scopes: vec![scope],
            requirements: vec![requirement],
            policies: vec![policy],
            canonical_paths: CanonicalPaths {
                model: "model/root".to_string(),
                actors: vec!["actor/owner".to_string()],
                referents: vec![],
                boundaries: vec![],
                edges: vec![],
                scopes: vec!["scope/default".to_string()],
                requirements: vec!["requirement/min".to_string()],
                policies: vec!["policy/default".to_string()],
            },
        }
    }

    #[test]
    fn carrier_is_sorted_by_referent_id_bytes_within_sort() {
        let model = model_with_referents(vec![
            ReferentDeclaration {
                id: ReferentId::from_bytes(id16(4)),
                sort: ReferentSortId(2),
            },
            ReferentDeclaration {
                id: ReferentId::from_bytes(id16(9)),
                sort: ReferentSortId(1),
            },
            ReferentDeclaration {
                id: ReferentId::from_bytes(id16(1)),
                sort: ReferentSortId(1),
            },
            ReferentDeclaration {
                id: ReferentId::from_bytes(id16(5)),
                sort: ReferentSortId(1),
            },
        ]);

        let carrier = Carrier::from_declared_model(&model, ReferentSortId(1));
        let ordered_ids: Vec<[u8; 16]> = carrier
            .referent_ids()
            .iter()
            .map(|id| id.as_bytes())
            .collect();

        assert_eq!(ordered_ids, vec![id16(1), id16(5), id16(9)]);
    }
}
