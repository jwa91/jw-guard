use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyKind {
    #[serde(rename = "ScopePolicy")]
    ScopePolicy,
    #[serde(rename = "PhaseSeparationPolicy")]
    PhaseSeparationPolicy,
    #[serde(rename = "EdgeBudgetPolicy")]
    EdgeBudgetPolicy,
    #[serde(rename = "PortProfilePolicy")]
    PortProfilePolicy,
    #[serde(rename = "TransportRoutesPolicy")]
    TransportRoutesPolicy,
}
