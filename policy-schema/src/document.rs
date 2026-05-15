use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::PolicyKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiVersion {
    #[serde(rename = "jw-guard/v1alpha1")]
    V1Alpha1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEnvelope<S, R> {
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    pub kind: PolicyKind,
    pub metadata: PolicyMetadata,
    pub scope: S,
    pub requirements: Vec<R>,
    #[serde(default)]
    pub declarations: PolicyDeclarations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeclarations {
    #[serde(default)]
    pub referents: Vec<ReferentDeclaration>,
    #[serde(default)]
    pub edges: Vec<EdgeDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferentDeclaration {
    pub name: String,
    pub sort: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeDeclaration {
    pub name: String,
    pub sort: u16,
    pub direction: EdgeDirection,
    pub first: String,
    pub second: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    Directed,
    Undirected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicyScope {
    pub target: ScopeTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTarget {
    Workspace,
    Package,
    Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicyRequirement {
    pub selector: ScopeSelector,
    pub constraint: ScopeConstraint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSelector {
    Source,
    Build,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeConstraint {
    InScope,
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseSeparationPolicyScope {
    pub lifecycle: PhaseLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseLifecycle {
    BuildRuntime,
    RuntimeOperations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseSeparationRequirement {
    pub producer: PhaseName,
    pub consumer: PhaseName,
    pub relation: PhaseRelation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseName {
    Build,
    Sign,
    Release,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseRelation {
    Isolated,
    ReadOnlyHandoff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBudgetPolicyScope {
    pub graph: GraphKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphKind {
    Dependency,
    RuntimeCall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBudgetRequirement {
    pub source: NodeClass,
    pub target: NodeClass,
    pub max_edges: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeClass {
    Service,
    Package,
    RuntimeComponent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortProfilePolicyScope {
    pub environment: PortEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortEnvironment {
    Development,
    Staging,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortProfileRequirement {
    pub profile: PortProfile,
    pub transport: TransportProtocol,
    pub port: u16,
    pub exposure: PortExposure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProfile {
    ControlPlane,
    DataPlane,
    Metrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortExposure {
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRoutesPolicyScope {
    pub topology: RouteTopology,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTopology {
    Cluster,
    Mesh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRouteRequirement {
    pub from: RouteEndpoint,
    pub to: RouteEndpoint,
    pub transport: TransportProtocol,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteEndpoint {
    Runtime,
    ControlPlane,
    AuditSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Http,
    Https,
    Grpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Allow,
    Deny,
}

pub type ScopePolicyDocument = PolicyEnvelope<ScopePolicyScope, ScopePolicyRequirement>;
pub type PhaseSeparationPolicyDocument =
    PolicyEnvelope<PhaseSeparationPolicyScope, PhaseSeparationRequirement>;
pub type EdgeBudgetPolicyDocument = PolicyEnvelope<EdgeBudgetPolicyScope, EdgeBudgetRequirement>;
pub type PortProfilePolicyDocument = PolicyEnvelope<PortProfilePolicyScope, PortProfileRequirement>;
pub type TransportRoutesPolicyDocument =
    PolicyEnvelope<TransportRoutesPolicyScope, TransportRouteRequirement>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDocument {
    ScopePolicy(ScopePolicyDocument),
    PhaseSeparationPolicy(PhaseSeparationPolicyDocument),
    EdgeBudgetPolicy(EdgeBudgetPolicyDocument),
    PortProfilePolicy(PortProfilePolicyDocument),
    TransportRoutesPolicy(TransportRoutesPolicyDocument),
}

impl PolicyDocument {
    pub fn kind(&self) -> PolicyKind {
        match self {
            Self::ScopePolicy(_) => PolicyKind::ScopePolicy,
            Self::PhaseSeparationPolicy(_) => PolicyKind::PhaseSeparationPolicy,
            Self::EdgeBudgetPolicy(_) => PolicyKind::EdgeBudgetPolicy,
            Self::PortProfilePolicy(_) => PolicyKind::PortProfilePolicy,
            Self::TransportRoutesPolicy(_) => PolicyKind::TransportRoutesPolicy,
        }
    }
}
