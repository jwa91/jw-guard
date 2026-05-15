#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Direction {
    Directed,
    Undirected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SurfaceFacing {
    A,
    B,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EndpointRole {
    From,
    To,
    EndpointA,
    EndpointB,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RequirementOperator {
    PresenceRequired,
    PresenceForbidden,
    PresenceOptional,
    CountEqual,
    CountMin,
    CountMax,
    SetIncludes,
    SetExcludes,
    SetEquals,
    TemporalBefore,
    TemporalAfter,
    TemporalWithin,
    RelationExists,
    RelationNotExists,
    RelationPathLengthMax,
    RelationEdgeCountMax,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ObservationKind {
    Measured,
    Inferred,
    Declared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ResolutionState {
    Resolved,
    Unresolved,
    Ambiguous,
    Conflicting,
}

