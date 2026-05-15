use alloc::vec::Vec;

use crate::name::SymbolicName;
use jw_guard_core::{Direction, RequirementOperator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredSpec {
    pub schema_version: SymbolicName,
    pub model: ModelSpec,
    pub actors: Vec<ActorSpec>,
    pub referents: Vec<ReferentSpec>,
    pub boundaries: Vec<BoundarySpec>,
    pub edges: Vec<EdgeSpec>,
    pub scopes: Vec<ScopeSpec>,
    pub requirements: Vec<RequirementSpec>,
    pub policies: Vec<PolicySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpec {
    pub name: SymbolicName,
    pub version: VersionSpec,
    pub declared_at_unix_seconds: u64,
    pub declared_by: SymbolicName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSpec {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorSpec {
    pub name: SymbolicName,
    pub role: SymbolicName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferentSpec {
    pub name: SymbolicName,
    pub sort: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySpec {
    pub name: SymbolicName,
    pub side_a_anchor: SymbolicName,
    pub side_b_anchor: SymbolicName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSpec {
    pub name: SymbolicName,
    pub sort: u16,
    pub direction: Direction,
    pub first: SymbolicName,
    pub second: SymbolicName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSpec {
    pub name: SymbolicName,
    pub referent_sort: u16,
    pub snapshot_unix_seconds: u64,
    pub namespace: SymbolicName,
    pub mapper_version: VersionSpec,
    pub predicate: ScopePredicateSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopePredicateSpec {
    All,
    HasTag(SymbolicName),
    NameEquals(SymbolicName),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementSpec {
    pub name: SymbolicName,
    pub sort: u16,
    pub operator: RequirementOperator,
    pub value: RequirementValueSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementValueSpec {
    Bool(bool),
    U64(u64),
    Name(SymbolicName),
    Names(Vec<SymbolicName>),
    DurationSeconds(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    pub name: SymbolicName,
    pub declared_by: SymbolicName,
    pub scope: SymbolicName,
    pub requirement: SymbolicName,
}
