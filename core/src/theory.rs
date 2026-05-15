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

/// Abstract model referent declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReferentDeclaration {
    pub id: ReferentId,
    pub sort: ReferentSort,
}

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

/// Typed edge declaration between two referents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EdgeDeclaration {
    pub id: EdgeId,
    pub sort: EdgeSort,
    pub from: ReferentId,
    pub to: ReferentId,
}

impl EdgeDeclaration {
    pub fn new(id: EdgeId, sort: EdgeSort, from: ReferentId, to: ReferentId) -> GuardResult<Self> {
        if from == to {
            return Err(GuardError::Invariant {
                field: "edge_declaration.distinct_ends",
            });
        }
        Ok(Self { id, sort, from, to })
    }
}

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
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum MembershipPredicateDeclaration {
    All,
    ReferentIds { ids: NonEmptyVec<ReferentId> },
    EdgeTo { edge_sort: EdgeSort, to: ReferentId },
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

/// Observation declaration mapped from evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObservationDeclaration {
    pub id: ObservationId,
    pub source: EvidenceSourceId,
    pub observed_referent: Option<ReferentId>,
    pub observed_sort: ReferentSort,
    pub at: UtcTimestamp,
    pub claim: TypedValue,
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
    pub evidence_basis: NonEmptyVec<ObservationId>,
    pub result: EvaluationResult,
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
