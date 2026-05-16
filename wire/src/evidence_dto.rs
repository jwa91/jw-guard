use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dto::WireVersionSpec;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireMappedEvidence {
    pub source: WireMappedSource,
    pub referents: Vec<WireMappedReferent>,
    pub property_claims: Vec<WireMappedPropertyClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireMappedSource {
    pub mapper: WireMapperIdentity,
    pub input_kind: String,
    pub observed_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireMapperIdentity {
    pub name: String,
    pub version: WireVersionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireMappedReferent {
    pub name: String,
    pub sort: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireMappedPropertyClaim {
    pub subject: String,
    pub property: String,
    pub value: WireMappedValue,
    pub observed_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireMappedValue {
    Bool { value: bool },
    U64 { value: u64 },
    Name { name: String },
    Names { names: Vec<String> },
    DurationSeconds { seconds: u64 },
}
