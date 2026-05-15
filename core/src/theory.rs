use alloc::{collections::BTreeSet, vec::Vec};

use crate::{
    error::{GuardError, GuardResult},
    id::{
        ActorId, BoundaryId, EdgeId, EvaluationId, EvidenceSourceId, ModelId, ObservationId,
        PolicyId, ReferentId, RequirementId, ScopeId, SurfaceId,
    },
    scalars::{NonEmptyString, NonEmptyVec, SemVer, UtcTimestamp},
};

/// Semantic type of a referent selected by a typed scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum ReferentSort {
    Actor,
    Boundary,
    Surface,
    Edge,
    StoredObject,
    DependencyEdge,
    TrustHandover,
    BoundaryPath,
    ProcessEvent,
    ReleaseArtifact,
    Custom { name: NonEmptyString },
}

/// Semantic type of an edge relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum EdgeSort {
    CrossesBoundary,
    DependsOn,
    Trusts,
    Signs,
    LogsTo,
    BacksUpTo,
    Contains,
    Serves,
    Builds,
    Custom { name: NonEmptyString },
}

/// Semantic class of requirement intent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum RequirementSort {
    Presence,
    Order,
    SetMembership,
    Count,
    Temporal,
    Relation,
    Custom { name: NonEmptyString },
}

/// Presence requirement operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum PresenceOperator {
    Required,
    Forbidden,
    Optional,
}

/// Ordering operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum OrderOperator {
    Exactly,
    AtLeast,
    AtMost,
}

/// Set operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum SetOperator {
    Includes,
    Excludes,
    Equals,
}

/// Count operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum CountOperator {
    Equal,
    Min,
    Max,
}

/// Temporal operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum TemporalOperator {
    Before,
    After,
    Within,
    Every,
}

/// Relation operators.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum RelationOperator {
    Exists,
    NotExists,
    PathLength,
    EdgeCount,
}

/// Unified requirement operator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind", content = "op"))]
pub enum RequirementOperator {
    Presence(PresenceOperator),
    Order(OrderOperator),
    Set(SetOperator),
    Count(CountOperator),
    Temporal(TemporalOperator),
    Relation(RelationOperator),
}

/// Type universe for requirement values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind", content = "value"))]
pub enum TypedValue {
    Bool(bool),
    U64(u64),
    String(NonEmptyString),
    Timestamp(UtcTimestamp),
    SemVer(SemVer),
    ReferentSort(ReferentSort),
    EdgeSort(EdgeSort),
}

/// One closed model declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModelDeclaration {
    pub id: ModelId,
    pub version: SemVer,
    pub declared_at: UtcTimestamp,
    pub declared_by: ActorId,
}

/// Accountable actor role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum ActorRole {
    Human,
    Service,
    System,
    External,
    Custom { name: NonEmptyString },
}

/// Accountable actor declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActorDeclaration {
    pub id: ActorId,
    pub role: ActorRole,
}

/// Foundational typed referent handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Referent {
    pub id: ReferentId,
    pub sort: ReferentSort,
}

/// Backward-compatible declaration alias for typed referents.
pub type ReferentDeclaration = Referent;

/// Boundary side marker.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum SideLabel {
    A,
    B,
}

/// One declared side of a boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SideDeclaration {
    pub label: SideLabel,
    pub anchor: ReferentId,
}

/// One declared boundary surface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SurfaceDeclaration {
    pub id: SurfaceId,
    pub boundary_id: BoundaryId,
    pub facing: SideLabel,
}

/// Abstract boundary declaration with exactly two sides and two surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    ) -> GuardResult<Self> {
        if side_a.label != SideLabel::A || side_b.label != SideLabel::B {
            return Err(GuardError::Invariant {
                field: "boundary_declaration.side_labels",
            });
        }
        if side_a.anchor == side_b.anchor {
            return Err(GuardError::Invariant {
                field: "boundary_declaration.distinct_anchors",
            });
        }
        if surface_a.boundary_id != id || surface_b.boundary_id != id {
            return Err(GuardError::Invariant {
                field: "boundary_declaration.surface_boundary",
            });
        }
        if surface_a.facing != SideLabel::A || surface_b.facing != SideLabel::B {
            return Err(GuardError::Invariant {
                field: "boundary_declaration.surface_labels",
            });
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

/// Foundational typed relation between referents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Edge {
    pub id: EdgeId,
    pub sort: EdgeSort,
    pub from: ReferentId,
    pub to: ReferentId,
}

impl Edge {
    pub fn new(id: EdgeId, sort: EdgeSort, from: ReferentId, to: ReferentId) -> GuardResult<Self> {
        if from == to {
            return Err(GuardError::Invariant {
                field: "edge_declaration.distinct_ends",
            });
        }
        Ok(Self { id, sort, from, to })
    }
}

/// Backward-compatible declaration alias for typed edges.
pub type EdgeDeclaration = Edge;

/// Deterministic context used to construct scope carriers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluationContextDeclaration {
    pub model_version: SemVer,
    pub namespace: Option<NonEmptyString>,
    pub boundary: Option<BoundaryId>,
    pub actor_authority: Option<ActorId>,
    pub snapshot_at: Option<UtcTimestamp>,
    pub evidence_source: Option<EvidenceSourceId>,
}

/// Typed membership predicate declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EdgeToPredicateDeclaration {
    pub source_sort: ReferentSort,
    pub edge_sort: EdgeSort,
    pub to: ReferentId,
}

/// Typed membership predicate declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum MembershipPredicateDeclaration {
    All,
    ReferentIds { ids: NonEmptyVec<ReferentId> },
    EdgeTo(EdgeToPredicateDeclaration),
}

/// Typed scope declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TypedScopeDeclaration {
    pub id: ScopeId,
    pub referent_sort: ReferentSort,
    pub context: EvaluationContextDeclaration,
    pub predicate: MembershipPredicateDeclaration,
}

impl TypedScopeDeclaration {
    pub fn new(
        id: ScopeId,
        referent_sort: ReferentSort,
        context: EvaluationContextDeclaration,
        predicate: MembershipPredicateDeclaration,
    ) -> GuardResult<Self> {
        if let MembershipPredicateDeclaration::EdgeTo(edge_to) = &predicate {
            if edge_to.source_sort != referent_sort {
                return Err(GuardError::Invariant {
                    field: "typed_scope_declaration.edge_to_source_sort",
                });
            }
        }

        Ok(Self {
            id,
            referent_sort,
            context,
            predicate,
        })
    }

    pub fn edge_to(
        id: ScopeId,
        context: EvaluationContextDeclaration,
        edge_to: EdgeToPredicateDeclaration,
    ) -> Self {
        Self {
            id,
            referent_sort: edge_to.source_sort.clone(),
            context,
            predicate: MembershipPredicateDeclaration::EdgeTo(edge_to),
        }
    }
}

/// Normative requirement declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequirementDeclaration {
    pub id: RequirementId,
    pub sort: RequirementSort,
    pub operator: RequirementOperator,
    pub value: TypedValue,
}

impl RequirementDeclaration {
    pub fn new(
        id: RequirementId,
        sort: RequirementSort,
        operator: RequirementOperator,
        value: TypedValue,
    ) -> GuardResult<Self> {
        if !operator_matches_value(&operator, &value) {
            return Err(GuardError::Invariant {
                field: "requirement_declaration.operator_value",
            });
        }
        if !sort_matches_operator(&sort, &operator) {
            return Err(GuardError::Invariant {
                field: "requirement_declaration.sort_operator",
            });
        }
        Ok(Self {
            id,
            sort,
            operator,
            value,
        })
    }
}

/// Policy declaration in minimum abstract form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyDeclaration {
    pub id: PolicyId,
    pub declared_by: ActorId,
    pub scope: ScopeId,
    pub requirement: RequirementId,
}

/// Evidence source declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvidenceSourceDeclaration {
    pub id: EvidenceSourceId,
    pub source_type: NonEmptyString,
    pub mapper: NonEmptyString,
    pub trust_assumption: NonEmptyString,
}

/// Provenance-carrying evidence atom.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvidenceItem {
    pub id: ObservationId,
    pub source: EvidenceSourceId,
    pub observed_referent: Option<ReferentId>,
    pub observed_sort: ReferentSort,
    pub at: UtcTimestamp,
    pub claim: TypedValue,
}

/// Backward-compatible declaration alias for evidence observations.
pub type ObservationDeclaration = EvidenceItem;

/// Explicit non-empty basis for evaluation evidence and assumptions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvidenceBasis {
    pub references: NonEmptyVec<ObservationId>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub assumptions: Vec<NonEmptyString>,
}

impl EvidenceBasis {
    pub fn new(
        references: NonEmptyVec<ObservationId>,
        assumptions: Vec<NonEmptyString>,
    ) -> GuardResult<Self> {
        let mut seen = BTreeSet::new();
        for reference in references.as_slice() {
            if !seen.insert(*reference) {
                return Err(GuardError::Invariant {
                    field: "evidence_basis.distinct_references",
                });
            }
        }
        Ok(Self {
            references,
            assumptions,
        })
    }

    pub fn from_references(references: NonEmptyVec<ObservationId>) -> GuardResult<Self> {
        Self::new(references, Vec::new())
    }
}

/// Evaluation outcome vocabulary.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum EvaluationResult {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
    ContradictoryEvidence,
    StaleEvidence,
}

/// Evaluation declaration binding policy and evidence basis.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluationDeclaration {
    pub id: EvaluationId,
    pub policy: PolicyId,
    pub evidence_basis: EvidenceBasis,
    pub result: EvaluationResult,
}

impl EvaluationDeclaration {
    pub fn new(
        id: EvaluationId,
        policy: PolicyId,
        evidence_basis: EvidenceBasis,
        result: EvaluationResult,
    ) -> Self {
        Self {
            id,
            policy,
            evidence_basis,
            result,
        }
    }
}

fn operator_matches_value(operator: &RequirementOperator, value: &TypedValue) -> bool {
    match operator {
        RequirementOperator::Presence(_) => matches!(value, TypedValue::Bool(_)),
        RequirementOperator::Order(_) | RequirementOperator::Count(_) => {
            matches!(value, TypedValue::U64(_))
        }
        RequirementOperator::Set(_) => matches!(
            value,
            TypedValue::String(_) | TypedValue::ReferentSort(_) | TypedValue::EdgeSort(_)
        ),
        RequirementOperator::Temporal(_) => {
            matches!(value, TypedValue::Timestamp(_) | TypedValue::U64(_))
        }
        RequirementOperator::Relation(_) => matches!(
            value,
            TypedValue::U64(_)
                | TypedValue::Bool(_)
                | TypedValue::ReferentSort(_)
                | TypedValue::EdgeSort(_)
        ),
    }
}

fn sort_matches_operator(sort: &RequirementSort, operator: &RequirementOperator) -> bool {
    matches!(
        (sort, operator),
        (RequirementSort::Presence, RequirementOperator::Presence(_))
            | (RequirementSort::Order, RequirementOperator::Order(_))
            | (RequirementSort::SetMembership, RequirementOperator::Set(_))
            | (RequirementSort::Count, RequirementOperator::Count(_))
            | (RequirementSort::Temporal, RequirementOperator::Temporal(_))
            | (RequirementSort::Relation, RequirementOperator::Relation(_))
            | (RequirementSort::Custom { .. }, _)
    )
}
