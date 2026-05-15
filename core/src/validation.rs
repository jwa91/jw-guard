use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::composites::{DeclaredModel, EvaluatedModel};
use crate::enums::{Direction, EndpointRole, RequirementOperator, SurfaceFacing};
use crate::id::{ActorId, ClaimId, EvidenceId, ReferentId, RequirementId, ScopeId, SideId, SourceId};
use crate::structs::{requirement_operator_value_compatible, TypedScopeDeclaration};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CoreViolation {
    DuplicateActorId(ActorId),
    DuplicateReferentId(ReferentId),
    DuplicateSideId(SideId),
    DuplicateScopeId(ScopeId),
    DuplicateRequirementId(RequirementId),
    DuplicatePolicyId(crate::id::PolicyId),
    DuplicateClaimId(ClaimId),
    DuplicateEvidenceId(EvidenceId),
    DuplicateSourceId(SourceId),
    BoundarySideMismatch(crate::id::BoundaryId),
    BoundarySurfaceMismatch(crate::id::BoundaryId),
    BoundarySideIdentityCollision(crate::id::BoundaryId),
    DirectedEdgeInvalidRoles(crate::id::EdgeId),
    UndirectedEdgeInvalidRoles(crate::id::EdgeId),
    EdgeEndpointMissing(crate::id::EdgeId, ReferentId),
    PolicyActorMissing(crate::id::PolicyId, ActorId),
    PolicyScopeMissing(crate::id::PolicyId, ScopeId),
    PolicyRequirementMissing(crate::id::PolicyId, RequirementId),
    ScopeSortUnknown(ScopeId),
    InvalidRequirementValueType(RequirementId, RequirementOperator),
    EvidenceClaimMissing(EvidenceId, ClaimId),
    EvidenceSourceMissing(EvidenceId, SourceId),
}

pub fn validate_declared_model(model: &DeclaredModel) -> Vec<CoreViolation> {
    let mut violations = Vec::new();

    collect_duplicates(
        model.actors.iter().map(|a| a.id),
        &mut violations,
        CoreViolation::DuplicateActorId,
    );
    collect_duplicates(
        model.referents.iter().map(|r| r.id),
        &mut violations,
        CoreViolation::DuplicateReferentId,
    );
    collect_duplicates(
        model.scopes.iter().map(|s| s.id),
        &mut violations,
        CoreViolation::DuplicateScopeId,
    );
    collect_duplicates(
        model.requirements.iter().map(|r| r.id),
        &mut violations,
        CoreViolation::DuplicateRequirementId,
    );
    collect_duplicates(
        model.policies.iter().map(|p| p.id),
        &mut violations,
        CoreViolation::DuplicatePolicyId,
    );

    let referent_ids: BTreeSet<_> = model.referents.iter().map(|r| r.id).collect();
    let actor_ids: BTreeSet<_> = model.actors.iter().map(|a| a.id).collect();
    let scope_ids: BTreeSet<_> = model.scopes.iter().map(|s| s.id).collect();
    let requirement_ids: BTreeSet<_> = model.requirements.iter().map(|r| r.id).collect();

    for boundary in &model.boundaries {
        if boundary.side_a.boundary_id != boundary.id || boundary.side_b.boundary_id != boundary.id {
            violations.push(CoreViolation::BoundarySideMismatch(boundary.id));
        }
        if boundary.surface_a.boundary_id != boundary.id || boundary.surface_b.boundary_id != boundary.id {
            violations.push(CoreViolation::BoundarySurfaceMismatch(boundary.id));
        }
        if boundary.side_a.id == boundary.side_b.id {
            violations.push(CoreViolation::BoundarySideIdentityCollision(boundary.id));
        }
        if boundary.surface_a.facing != SurfaceFacing::A || boundary.surface_b.facing != SurfaceFacing::B {
            violations.push(CoreViolation::BoundarySurfaceMismatch(boundary.id));
        }
    }

    let mut side_ids = BTreeSet::new();
    for boundary in &model.boundaries {
        if !side_ids.insert(boundary.side_a.id) {
            violations.push(CoreViolation::DuplicateSideId(boundary.side_a.id));
        }
        if !side_ids.insert(boundary.side_b.id) {
            violations.push(CoreViolation::DuplicateSideId(boundary.side_b.id));
        }
    }

    for edge in &model.edges {
        if !referent_ids.contains(&edge.first.referent_id) {
            violations.push(CoreViolation::EdgeEndpointMissing(edge.id, edge.first.referent_id));
        }
        if !referent_ids.contains(&edge.second.referent_id) {
            violations.push(CoreViolation::EdgeEndpointMissing(edge.id, edge.second.referent_id));
        }
        match edge.direction {
            Direction::Directed => {
                let roles_ok = edge.first.role == EndpointRole::From && edge.second.role == EndpointRole::To;
                if !roles_ok {
                    violations.push(CoreViolation::DirectedEdgeInvalidRoles(edge.id));
                }
            }
            Direction::Undirected => {
                let roles_ok = edge.first.role == EndpointRole::EndpointA && edge.second.role == EndpointRole::EndpointB;
                if !roles_ok {
                    violations.push(CoreViolation::UndirectedEdgeInvalidRoles(edge.id));
                }
            }
        }
    }

    for scope in &model.scopes {
        if !model.referents.iter().any(|r| r.sort == scope.referent_sort) {
            violations.push(CoreViolation::ScopeSortUnknown(scope.id));
        }
    }

    for requirement in &model.requirements {
        if !requirement_operator_value_compatible(requirement.operator, &requirement.value) {
            violations.push(CoreViolation::InvalidRequirementValueType(
                requirement.id,
                requirement.operator,
            ));
        }
    }

    for policy in &model.policies {
        if !actor_ids.contains(&policy.declared_by) {
            violations.push(CoreViolation::PolicyActorMissing(policy.id, policy.declared_by));
        }
        if !scope_ids.contains(&policy.scope) {
            violations.push(CoreViolation::PolicyScopeMissing(policy.id, policy.scope));
        }
        if !requirement_ids.contains(&policy.requirement) {
            violations.push(CoreViolation::PolicyRequirementMissing(policy.id, policy.requirement));
        }
    }

    violations
}

pub fn validate_evaluated_model(model: &EvaluatedModel) -> Vec<CoreViolation> {
    let mut violations = validate_declared_model(&model.declared);

    collect_duplicates(
        model.evidence_basis.sources.iter().map(|s| s.id),
        &mut violations,
        CoreViolation::DuplicateSourceId,
    );
    collect_duplicates(
        model.evidence_basis.claims.iter().map(|c| c.id),
        &mut violations,
        CoreViolation::DuplicateClaimId,
    );
    collect_duplicates(
        model.evidence_basis.evidence_items.iter().map(|e| e.id),
        &mut violations,
        CoreViolation::DuplicateEvidenceId,
    );

    let source_ids: BTreeSet<_> = model.evidence_basis.sources.iter().map(|s| s.id).collect();
    let claim_ids: BTreeSet<_> = model.evidence_basis.claims.iter().map(|c| c.id).collect();

    for evidence in &model.evidence_basis.evidence_items {
        if !source_ids.contains(&evidence.source) {
            violations.push(CoreViolation::EvidenceSourceMissing(evidence.id, evidence.source));
        }
        if !claim_ids.contains(&evidence.claim) {
            violations.push(CoreViolation::EvidenceClaimMissing(evidence.id, evidence.claim));
        }
    }

    violations
}

fn collect_duplicates<T, I, F>(items: I, violations: &mut Vec<CoreViolation>, mk: F)
where
    T: Ord + Copy,
    I: Iterator<Item = T>,
    F: Fn(T) -> CoreViolation,
{
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            violations.push(mk(item));
        }
    }
}

pub fn deterministic_scope_order(scopes: &mut [TypedScopeDeclaration]) {
    scopes.sort_by_key(|scope| scope.id);
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::composites::DeclaredModel;
    use crate::scalars::{CanonicalName, SemVer, Timestamp};
    use crate::structs::{
        ActorDeclaration, BoundaryDeclaration, CanonicalPaths, EdgeDeclaration, Endpoint, EvaluationContext,
        MembershipPredicate, ModelDeclaration, PolicyDeclaration, ReferentDeclaration, RequirementDeclaration,
        RequirementValue, SideDeclaration, SurfaceDeclaration, TypedScopeDeclaration,
    };

    fn id16(v: u8) -> [u8; 16] {
        [v; 16]
    }

    fn base_declared_model() -> DeclaredModel {
        let model = ModelDeclaration {
            id: crate::id::ModelId::from_bytes(id16(1)),
            version: SemVer::new(0, 1, 0),
            declared_at: Timestamp::from_unix_seconds(1),
            declared_by: crate::id::ActorId::from_bytes(id16(2)),
        };

        let actor = ActorDeclaration {
            id: crate::id::ActorId::from_bytes(id16(2)),
            role: CanonicalName::new("owner".to_string()).expect("valid canonical actor role"),
        };

        let referent_a = ReferentDeclaration {
            id: crate::id::ReferentId::from_bytes(id16(3)),
            sort: crate::structs::ReferentSortId(1),
        };
        let referent_b = ReferentDeclaration {
            id: crate::id::ReferentId::from_bytes(id16(4)),
            sort: crate::structs::ReferentSortId(1),
        };

        let boundary_id = crate::id::BoundaryId::from_bytes(id16(5));
        let boundary = BoundaryDeclaration {
            id: boundary_id,
            side_a: SideDeclaration {
                id: crate::id::SideId::from_bytes(id16(6)),
                boundary_id,
                anchor_referent: referent_a.id,
            },
            side_b: SideDeclaration {
                id: crate::id::SideId::from_bytes(id16(7)),
                boundary_id,
                anchor_referent: referent_b.id,
            },
            surface_a: SurfaceDeclaration {
                id: crate::id::SurfaceId::from_bytes(id16(8)),
                boundary_id,
                facing: SurfaceFacing::A,
            },
            surface_b: SurfaceDeclaration {
                id: crate::id::SurfaceId::from_bytes(id16(9)),
                boundary_id,
                facing: SurfaceFacing::B,
            },
        };

        let edge = EdgeDeclaration {
            id: crate::id::EdgeId::from_bytes(id16(10)),
            sort: crate::structs::EdgeSortId(1),
            direction: Direction::Directed,
            first: Endpoint {
                role: EndpointRole::From,
                referent_id: referent_a.id,
            },
            second: Endpoint {
                role: EndpointRole::To,
                referent_id: referent_b.id,
            },
        };

        let scope = TypedScopeDeclaration {
            id: crate::id::ScopeId::from_bytes(id16(11)),
            referent_sort: crate::structs::ReferentSortId(1),
            context: EvaluationContext {
                model_version: SemVer::new(0, 1, 0),
                snapshot: Timestamp::from_unix_seconds(1),
                namespace: CanonicalName::new("default".to_string()).expect("valid canonical namespace"),
                mapper_version: SemVer::new(0, 1, 0),
            },
            predicate: MembershipPredicate::All,
        };

        let requirement = RequirementDeclaration {
            id: crate::id::RequirementId::from_bytes(id16(12)),
            sort: crate::structs::RequirementSortId(1),
            operator: RequirementOperator::CountMin,
            value: RequirementValue::U64(1),
        };

        let policy = PolicyDeclaration {
            id: crate::id::PolicyId::from_bytes(id16(13)),
            declared_by: actor.id,
            scope: scope.id,
            requirement: requirement.id,
        };

        DeclaredModel {
            model,
            actors: vec![actor],
            referents: vec![referent_a, referent_b],
            boundaries: vec![boundary],
            edges: vec![edge],
            scopes: vec![scope],
            requirements: vec![requirement],
            policies: vec![policy],
            canonical_paths: CanonicalPaths {
                model: "model/root".to_string(),
                actors: vec!["actor/owner".to_string()],
                referents: vec!["referent/node/a".to_string(), "referent/node/b".to_string()],
                boundaries: vec!["boundary/main".to_string()],
                edges: vec!["edge/depends/main".to_string()],
                scopes: vec!["scope/default".to_string()],
                requirements: vec!["requirement/min".to_string()],
                policies: vec!["policy/default".to_string()],
            },
        }
    }

    #[test]
    fn declared_model_passes_structural_validation() {
        let model = base_declared_model();
        let violations = validate_declared_model(&model);
        assert!(
            violations.is_empty(),
            "expected zero structural violations, got: {violations:?}"
        );
    }

    #[test]
    fn detects_operator_value_mismatch() {
        let mut model = base_declared_model();
        model.requirements[0].operator = RequirementOperator::SetEquals;
        model.requirements[0].value = RequirementValue::U64(10);

        let violations = validate_declared_model(&model);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CoreViolation::InvalidRequirementValueType(..))),
            "expected InvalidRequirementValueType, got {violations:?}"
        );
    }
}

