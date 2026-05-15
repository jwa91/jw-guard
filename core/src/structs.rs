use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::enums::{Direction, EndpointRole, ObservationKind, RequirementOperator, ResolutionState, SurfaceFacing};
use crate::id::{
    ActorId, BoundaryId, ClaimId, EdgeId, EvidenceId, ModelId, PolicyId, PredicateId, ReferentId, RequirementId,
    ScopeId, SideId, SourceId, SurfaceId,
};
use crate::scalars::{CanonicalName, SemVer, Sha256Digest, Timestamp};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelDeclaration {
    pub id: ModelId,
    pub version: SemVer,
    pub declared_at: Timestamp,
    pub declared_by: ActorId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActorDeclaration {
    pub id: ActorId,
    pub role: CanonicalName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReferentSortId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EdgeSortId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequirementSortId(pub u16);

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReferentDeclaration {
    pub id: ReferentId,
    pub sort: ReferentSortId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SideDeclaration {
    pub id: SideId,
    pub boundary_id: BoundaryId,
    pub anchor_referent: ReferentId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SurfaceDeclaration {
    pub id: SurfaceId,
    pub boundary_id: BoundaryId,
    pub facing: SurfaceFacing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BoundaryDeclaration {
    pub id: BoundaryId,
    pub side_a: SideDeclaration,
    pub side_b: SideDeclaration,
    pub surface_a: SurfaceDeclaration,
    pub surface_b: SurfaceDeclaration,
}

impl BoundaryDeclaration {
    pub fn new(
        id: BoundaryId,
        side_a: SideDeclaration,
        side_b: SideDeclaration,
        surface_a: SurfaceDeclaration,
        surface_b: SurfaceDeclaration,
    ) -> Result<Self, ConstructionViolation> {
        if side_a.id == side_b.id {
            return Err(ConstructionViolation::BoundarySideIdentityCollision);
        }
        if side_a.boundary_id != id || side_b.boundary_id != id {
            return Err(ConstructionViolation::BoundarySideMismatch);
        }
        if surface_a.boundary_id != id || surface_b.boundary_id != id {
            return Err(ConstructionViolation::BoundarySurfaceMismatch);
        }
        if surface_a.facing != SurfaceFacing::A || surface_b.facing != SurfaceFacing::B {
            return Err(ConstructionViolation::BoundarySurfaceFacingMismatch);
        }
        Ok(Self {
            id,
            side_a,
            side_b,
            surface_a,
            surface_b,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Endpoint {
    pub role: EndpointRole,
    pub referent_id: ReferentId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EdgeDeclaration {
    pub id: EdgeId,
    pub sort: EdgeSortId,
    pub direction: Direction,
    pub first: Endpoint,
    pub second: Endpoint,
}

impl EdgeDeclaration {
    pub fn new(
        id: EdgeId,
        sort: EdgeSortId,
        direction: Direction,
        first: Endpoint,
        second: Endpoint,
    ) -> Result<Self, ConstructionViolation> {
        match direction {
            Direction::Directed => {
                if first.role != EndpointRole::From || second.role != EndpointRole::To {
                    return Err(ConstructionViolation::DirectedEdgeInvalidRoles);
                }
            }
            Direction::Undirected => {
                if first.role != EndpointRole::EndpointA || second.role != EndpointRole::EndpointB {
                    return Err(ConstructionViolation::UndirectedEdgeInvalidRoles);
                }
            }
        }
        Ok(Self {
            id,
            sort,
            direction,
            first,
            second,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluationContext {
    pub model_version: SemVer,
    pub snapshot: Timestamp,
    pub namespace: CanonicalName,
    pub mapper_version: SemVer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MembershipPredicate {
    All,
    HasTag(CanonicalName),
    NameEquals(CanonicalName),
    PredicateRef(PredicateId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TypedScopeDeclaration {
    pub id: ScopeId,
    pub referent_sort: ReferentSortId,
    pub context: EvaluationContext,
    pub predicate: MembershipPredicate,
}

impl TypedScopeDeclaration {
    pub fn new(
        id: ScopeId,
        referent_sort: ReferentSortId,
        context: EvaluationContext,
        predicate: MembershipPredicate,
    ) -> Self {
        Self {
            id,
            referent_sort,
            context,
            predicate,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RequirementValue {
    Bool(bool),
    U64(u64),
    Name(CanonicalName),
    Names(Vec<CanonicalName>),
    DurationSeconds(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequirementDeclaration {
    pub id: RequirementId,
    pub sort: RequirementSortId,
    pub operator: RequirementOperator,
    pub value: RequirementValue,
}

impl RequirementDeclaration {
    pub fn new(
        id: RequirementId,
        sort: RequirementSortId,
        operator: RequirementOperator,
        value: RequirementValue,
    ) -> Result<Self, ConstructionViolation> {
        if !requirement_operator_value_compatible(operator, &value) {
            return Err(ConstructionViolation::InvalidRequirementValueType);
        }
        Ok(Self {
            id,
            sort,
            operator,
            value,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyDeclaration {
    pub id: PolicyId,
    pub declared_by: ActorId,
    pub scope: ScopeId,
    pub requirement: RequirementId,
}

impl PolicyDeclaration {
    pub fn new(id: PolicyId, declared_by: ActorId, scope: ScopeId, requirement: RequirementId) -> Self {
        Self {
            id,
            declared_by,
            scope,
            requirement,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SourceDeclaration {
    pub id: SourceId,
    pub source_type: CanonicalName,
    pub mapper: CanonicalName,
    pub trust_assumption: CanonicalName,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Claim {
    pub id: ClaimId,
    pub kind: ObservationKind,
    pub subject: ReferentId,
    pub snapshot: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvidenceItem {
    pub id: EvidenceId,
    pub source: SourceId,
    pub claim: ClaimId,
    pub resolution: ResolutionState,
    pub recorded_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluationResult {
    pub outcome: EvaluationOutcome,
    pub reason: CanonicalName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EvaluationOutcome {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
    ContradictoryEvidence,
    StaleEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluationDeclaration {
    pub id: crate::id::EvaluationId,
    pub policy: PolicyId,
    pub evidence_basis: Vec<EvidenceId>,
    pub result: EvaluationResult,
    pub chain_hash: Sha256Digest,
    pub prev_chain_hash: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConstructionViolation {
    BoundarySideMismatch,
    BoundarySurfaceMismatch,
    BoundarySurfaceFacingMismatch,
    BoundarySideIdentityCollision,
    DirectedEdgeInvalidRoles,
    UndirectedEdgeInvalidRoles,
    InvalidRequirementValueType,
}

impl fmt::Display for ConstructionViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstructionViolation::BoundarySideMismatch => write!(f, "side boundary ids must match boundary id"),
            ConstructionViolation::BoundarySurfaceMismatch => {
                write!(f, "surface boundary ids must match boundary id")
            }
            ConstructionViolation::BoundarySurfaceFacingMismatch => {
                write!(f, "surfaces must be facing A and B in canonical order")
            }
            ConstructionViolation::BoundarySideIdentityCollision => {
                write!(f, "boundary sides must have distinct side ids")
            }
            ConstructionViolation::DirectedEdgeInvalidRoles => {
                write!(f, "directed edge must use from/to endpoint roles")
            }
            ConstructionViolation::UndirectedEdgeInvalidRoles => {
                write!(f, "undirected edge must use endpoint-a/endpoint-b roles")
            }
            ConstructionViolation::InvalidRequirementValueType => {
                write!(f, "requirement value type is incompatible with operator")
            }
        }
    }
}

pub(crate) fn requirement_operator_value_compatible(
    operator: RequirementOperator,
    value: &RequirementValue,
) -> bool {
    match operator {
        RequirementOperator::PresenceRequired
        | RequirementOperator::PresenceForbidden
        | RequirementOperator::PresenceOptional => matches!(value, RequirementValue::Bool(_)),
        RequirementOperator::CountEqual
        | RequirementOperator::CountMin
        | RequirementOperator::CountMax
        | RequirementOperator::RelationPathLengthMax
        | RequirementOperator::RelationEdgeCountMax => matches!(value, RequirementValue::U64(_)),
        RequirementOperator::SetIncludes | RequirementOperator::SetExcludes | RequirementOperator::SetEquals => {
            matches!(value, RequirementValue::Names(_))
        }
        RequirementOperator::TemporalBefore
        | RequirementOperator::TemporalAfter
        | RequirementOperator::TemporalWithin => matches!(value, RequirementValue::DurationSeconds(_)),
        RequirementOperator::RelationExists | RequirementOperator::RelationNotExists => {
            matches!(value, RequirementValue::Bool(_))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalPaths {
    pub model: String,
    pub actors: Vec<String>,
    pub referents: Vec<String>,
    pub boundaries: Vec<String>,
    pub edges: Vec<String>,
    pub scopes: Vec<String>,
    pub requirements: Vec<String>,
    pub policies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn id16(v: u8) -> [u8; 16] {
        [v; 16]
    }

    #[test]
    fn boundary_constructor_rejects_mismatched_facing() {
        let boundary_id = BoundaryId::from_bytes(id16(1));
        let side_a = SideDeclaration {
            id: SideId::from_bytes(id16(2)),
            boundary_id,
            anchor_referent: ReferentId::from_bytes(id16(3)),
        };
        let side_b = SideDeclaration {
            id: SideId::from_bytes(id16(4)),
            boundary_id,
            anchor_referent: ReferentId::from_bytes(id16(5)),
        };
        let surface_a = SurfaceDeclaration {
            id: SurfaceId::from_bytes(id16(6)),
            boundary_id,
            facing: SurfaceFacing::B,
        };
        let surface_b = SurfaceDeclaration {
            id: SurfaceId::from_bytes(id16(7)),
            boundary_id,
            facing: SurfaceFacing::A,
        };

        let result = BoundaryDeclaration::new(boundary_id, side_a, side_b, surface_a, surface_b);
        assert_eq!(
            result,
            Err(ConstructionViolation::BoundarySurfaceFacingMismatch)
        );
    }

    #[test]
    fn requirement_constructor_rejects_operator_value_mismatch() {
        let result = RequirementDeclaration::new(
            RequirementId::from_bytes(id16(1)),
            RequirementSortId(1),
            RequirementOperator::CountMin,
            RequirementValue::Bool(true),
        );

        assert_eq!(result, Err(ConstructionViolation::InvalidRequirementValueType));
    }

    #[test]
    fn requirement_constructor_accepts_compatible_value() {
        let result = RequirementDeclaration::new(
            RequirementId::from_bytes(id16(2)),
            RequirementSortId(1),
            RequirementOperator::SetIncludes,
            RequirementValue::Names(vec![CanonicalName::new("tls".to_string()).expect("valid name")]),
        );
        assert!(result.is_ok());
    }
}

