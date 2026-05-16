use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireDeclaredSpec {
    pub schema_version: String,
    pub model: WireModelSpec,
    pub actors: Vec<WireActorSpec>,
    pub referents: Vec<WireReferentSpec>,
    pub boundaries: Vec<WireBoundarySpec>,
    pub edges: Vec<WireEdgeSpec>,
    pub scopes: Vec<WireScopeSpec>,
    pub requirements: Vec<WireRequirementSpec>,
    pub policies: Vec<WirePolicySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireModelSpec {
    pub name: String,
    pub version: WireVersionSpec,
    pub declared_at_unix_seconds: u64,
    pub declared_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireVersionSpec {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireActorSpec {
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireReferentSpec {
    pub name: String,
    pub sort: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireBoundarySpec {
    pub name: String,
    pub side_a_anchor: String,
    pub side_b_anchor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireEdgeSpec {
    pub name: String,
    pub sort: u16,
    pub direction: WireDirection,
    pub first: String,
    pub second: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireScopeSpec {
    pub name: String,
    pub referent_sort: u16,
    pub snapshot_unix_seconds: u64,
    pub namespace: String,
    pub mapper_version: WireVersionSpec,
    pub predicate: WireScopePredicateSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireScopePredicateSpec {
    All,
    HasTag { tag: String },
    NameEquals { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireRequirementSpec {
    pub name: String,
    pub sort: u16,
    pub operator: WireRequirementOperator,
    pub value: WireRequirementValueSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRequirementValueSpec {
    Bool { value: bool },
    U64 { value: u64 },
    Name { name: String },
    Names { names: Vec<String> },
    DurationSeconds { seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WirePolicySpec {
    pub name: String,
    pub declared_by: String,
    pub scope: String,
    pub requirement: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WireDirection {
    Directed,
    Undirected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WireRequirementOperator {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema, Default)]
pub enum ExplicitOptionWire<T> {
    #[default]
    Unspecified,
    ExplicitNone,
    ExplicitSome(T),
}

impl<T> ExplicitOptionWire<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, Self::Unspecified)
    }
}

impl<'de, T> Deserialize<'de> for ExplicitOptionWire<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<T>::deserialize(deserializer)?;
        Ok(match value {
            Some(item) => Self::ExplicitSome(item),
            None => Self::ExplicitNone,
        })
    }
}
