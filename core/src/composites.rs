use alloc::vec::Vec;

use crate::{
    enums::{
        Capability, CredentialStrength, DefaultAction, ExternalProtocol, FailMode, GateVerdict,
        IdentityKind, LayerGateStatus, LayerHardness, LayerName, OutsideWorldClass, PolicyStatus,
        PolicyType, ReviewRate, RouteDecision, ServiceId, ServiceMode, Severity, TransferState,
        TrustBasis, VerificationKind,
    },
    error::{GuardError, GuardResult},
    id::{
        ActorId, ArtifactId, CredentialId, DecisionId, EdgeId, EnforcerId, EnvironmentId, EventId,
        ExceptionId, GateId, IdentityId, ManifestId, PolicyId, RouteId, ScopeId, ServiceInstanceId,
        TransferId, TrustId, ZoneId,
    },
    scalars::{
        ByteSize, ContractViolation, GlobPattern, MediaType, NonEmptyString, NonEmptyVec, Port,
        SemVer, Sha256, Signature, UtcTimestamp,
    },
    structs::{Boundary, BoundaryEnd, Gate, Layer, ScopeConstraint, Surface, Trust},
};

/// Integrity evidence required for an artifact crossing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum IntegrityRequirement {
    /// No integrity material is required by this contract.
    None,
    /// A content hash is required.
    Hash,
    /// A signature is required and implies a content hash.
    Signature,
}

impl IntegrityRequirement {
    /// Returns whether this requirement includes a content hash.
    pub const fn requires_hash(self) -> bool {
        matches!(self, Self::Hash | Self::Signature)
    }

    /// Returns whether this requirement includes a signature.
    pub const fn requires_signature(self) -> bool {
        matches!(self, Self::Signature)
    }
}

/// Actor that caused a workflow or orchestration event.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum ActorRef {
    /// A concrete identity in the security model.
    Identity {
        /// Acting identity.
        identity_id: IdentityId,
    },
    /// The system or a policy engine acted automatically.
    System,
}

/// Type signature for payloads permitted to cross a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArtifactContract {
    /// Media types that may pass.
    pub allowed_media_types: NonEmptyVec<MediaType>,
    /// Glob patterns that must not appear in content.
    pub forbidden_globs: Vec<GlobPattern>,
    /// Integrity evidence required for passage.
    pub integrity: IntegrityRequirement,
    /// Maximum size in bytes.
    pub max_bytes: Option<ByteSize>,
}

impl ArtifactContract {
    /// Creates an artifact contract.
    pub fn new(
        allowed_media_types: NonEmptyVec<MediaType>,
        forbidden_globs: Vec<GlobPattern>,
        integrity: IntegrityRequirement,
        max_bytes: Option<ByteSize>,
    ) -> Self {
        Self {
            allowed_media_types,
            forbidden_globs,
            integrity,
            max_bytes,
        }
    }

    /// Creates an artifact contract from legacy hash/signature booleans.
    pub fn from_flags(
        allowed_media_types: NonEmptyVec<MediaType>,
        forbidden_globs: Vec<GlobPattern>,
        requires_hash: bool,
        requires_signature: bool,
        max_bytes: Option<ByteSize>,
    ) -> GuardResult<Self> {
        if requires_signature && !requires_hash {
            return Err(GuardError::Invariant {
                field: "artifact_contract.signature_requires_hash",
            });
        }
        let integrity = match (requires_hash, requires_signature) {
            (_, true) => IntegrityRequirement::Signature,
            (true, false) => IntegrityRequirement::Hash,
            (false, false) => IntegrityRequirement::None,
        };
        Ok(Self {
            allowed_media_types,
            forbidden_globs,
            integrity,
            max_bytes,
        })
    }

    /// Returns whether this contract requires a content hash.
    pub const fn requires_hash(&self) -> bool {
        self.integrity.requires_hash()
    }

    /// Returns whether this contract requires a signature.
    pub const fn requires_signature(&self) -> bool {
        self.integrity.requires_signature()
    }
}

/// Complete protection posture of one boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BoundarySpec {
    /// Boundary being protected.
    pub boundary: Boundary,
    /// Layers protecting the boundary.
    pub layers: Vec<Layer>,
    /// Exactly two surfaces, facing A then facing B.
    pub surfaces: [Surface; 2],
}

impl BoundarySpec {
    /// Creates a boundary spec.
    pub fn new(boundary: Boundary, layers: Vec<Layer>, surfaces: [Surface; 2]) -> Self {
        Self {
            boundary,
            layers,
            surfaces,
        }
    }

    /// Returns the maximum hardness among all layers.
    pub fn effective_hardness(&self) -> Option<LayerHardness> {
        self.layers.iter().map(|layer| layer.hardness).max()
    }

    /// Returns fail-closed when any layer is fail-closed.
    pub fn effective_fail_mode(&self) -> FailMode {
        if self
            .layers
            .iter()
            .any(|layer| layer.fail_mode == FailMode::FailClosed)
        {
            FailMode::FailClosed
        } else {
            FailMode::FailOpen
        }
    }
}

/// Complete route policy: contract, gates, and required trust.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Policy {
    /// Policy identifier.
    pub id: PolicyId,
    /// Route this policy controls.
    pub route_id: RouteId,
    /// Payload contract.
    pub contract: ArtifactContract,
    /// Ordered route gates.
    pub gates: NonEmptyVec<Gate>,
    /// Trust required for passage.
    pub required_trust: NonEmptyVec<TrustRequirement>,
    /// Policy status.
    pub status: PolicyStatus,
    /// Semantic version.
    pub version: SemVer,
    /// Declaration timestamp.
    pub declared_at: UtcTimestamp,
    /// Declaring identity.
    pub declared_by: IdentityId,
}

/// Required trust shape for a route policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustRequirement {
    /// Required identity category.
    pub role: IdentityKind,
    /// Minimum credential strength.
    pub minimum_credential: CredentialStrength,
    /// Required capabilities.
    pub required_capabilities: NonEmptyVec<Capability>,
}

/// Access control decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind"))]
pub enum AccessDecision {
    /// Denial before any gate evaluates.
    PreGateDenial(PreGateDenial),
    /// Evaluation at a concrete gate.
    GateEvaluation(GateEvaluation),
}

/// Denial before any route gate runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreGateDenial {
    /// Decision identifier.
    pub id: DecisionId,
    /// Identity attempting access.
    pub identity_id: IdentityId,
    /// Route attempted.
    pub route_id: RouteId,
    /// Denial reason.
    pub reason: PreGateReason,
    /// Evaluation timestamp.
    pub evaluated_at: UtcTimestamp,
    /// Hash-chain link.
    pub chain_hash: Sha256,
    /// Previous hash-chain link.
    pub prev_chain_hash: Sha256,
}

/// Reason for a pre-gate denial.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum PreGateReason {
    /// Referenced route is disabled.
    RouteDisabled,
    /// Referenced policy is not active.
    PolicyNotActive {
        /// Non-active policy identifier.
        policy_id: PolicyId,
    },
}

/// Evaluation at a concrete gate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GateEvaluation {
    /// Decision identifier.
    pub id: DecisionId,
    /// Identity attempting access.
    pub identity_id: IdentityId,
    /// Credential presented.
    pub credential_id: CredentialId,
    /// Scope requested.
    pub scope_id: ScopeId,
    /// Gate evaluated.
    pub gate_id: GateId,
    /// Capabilities requested.
    pub requested_capabilities: NonEmptyVec<Capability>,
    /// Gate verdict.
    pub verdict: GateVerdict,
    /// Denial reason, if denied.
    pub reason: Option<GateDenialReason>,
    /// Evaluation timestamp.
    pub evaluated_at: UtcTimestamp,
    /// Hash-chain link.
    pub chain_hash: Sha256,
    /// Previous hash-chain link.
    pub prev_chain_hash: Sha256,
}

/// Reason for a gate denial.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "kind"))]
pub enum GateDenialReason {
    /// Identity does not hold required trust.
    IdentityNotTrusted {
        /// Expected trust, when known.
        expected_trust: Option<TrustId>,
    },
    /// Presented credential is weaker than required.
    CredentialInsufficient {
        /// Required strength.
        required: CredentialStrength,
        /// Presented strength.
        presented: CredentialStrength,
    },
    /// Requested capability is absent from the scope.
    CapabilityNotInScope {
        /// Missing capabilities.
        missing: NonEmptyVec<Capability>,
    },
    /// Scope constraint was violated.
    ScopeConstraintViolated {
        /// Violated constraint.
        constraint: ScopeConstraint,
    },
    /// Required gate verification failed.
    GateVerificationFailed {
        /// Failed verification.
        verification: VerificationKind,
    },
    /// Artifact contract was violated.
    ContractViolated {
        /// Violation detail.
        detail: ContractViolation,
    },
}

/// Traceable trust chain from root trust to a leaf trust.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrustChain {
    /// Root bootstrap trust.
    pub root: Trust,
    /// Ordered links from root outward.
    pub links: Vec<Trust>,
    /// Terminal trust being validated.
    pub leaf: Trust,
    /// Whether every link currently validates.
    pub chain_valid: bool,
}

impl TrustChain {
    /// Creates a trust chain and checks local shape invariants.
    pub fn new(
        root: Trust,
        links: Vec<Trust>,
        leaf: Trust,
        chain_valid: bool,
    ) -> GuardResult<Self> {
        if root.basis != TrustBasis::SystemBootstrap {
            return Err(GuardError::Invariant {
                field: "trust_chain.root_basis",
            });
        }
        if links.last().unwrap_or(&root) != &leaf {
            return Err(GuardError::Invariant {
                field: "trust_chain.leaf",
            });
        }
        Ok(Self {
            root,
            links,
            leaf,
            chain_valid,
        })
    }
}

/// Pure aggregate of the atomic and fundamental type layers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityModel {
    /// Model schema version.
    pub model_version: SemVer,
    /// Zones declared in the model.
    pub zones: Vec<crate::structs::Zone>,
    /// Boundary specs declared in the model.
    pub boundary_specs: Vec<BoundarySpec>,
    /// Routes declared in the model.
    pub routes: Vec<crate::structs::Route>,
    /// Policies declared in the model.
    pub policies: Vec<Policy>,
    /// Identities declared in the model.
    pub identities: Vec<crate::structs::Identity>,
    /// Scopes declared in the model.
    pub scopes: Vec<crate::structs::Scope>,
    /// Credentials declared in the model.
    pub credentials: Vec<crate::structs::Credential>,
    /// Trust grants declared in the model.
    pub trusts: Vec<Trust>,
}

/// Concrete artifact metadata used by transfer workflow types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArtifactDescriptor {
    /// Artifact identifier.
    pub id: ArtifactId,
    /// Artifact content hash.
    pub hash: Sha256,
    /// Artifact media type.
    pub media_type: MediaType,
    /// Artifact byte size.
    pub byte_size: ByteSize,
    /// Producing identity.
    pub producer_identity: IdentityId,
    /// Optional producer signature.
    pub signature: Option<Signature>,
}

/// Intent to transfer an artifact over a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransferIntent {
    /// Transfer identifier.
    pub id: TransferId,
    /// Route requested.
    pub route_id: RouteId,
    /// Request timestamp.
    pub requested_at: UtcTimestamp,
    /// Requesting identity.
    pub requested_by: IdentityId,
    /// Artifact to transfer.
    pub artifact: ArtifactDescriptor,
}

/// Verdict for a transfer intent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransferVerdict {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Route decided.
    pub route_id: RouteId,
    /// Decision timestamp.
    pub decided_at: UtcTimestamp,
    /// Actor that made the decision.
    pub decided_by: ActorRef,
    /// Accepted or rejected decision.
    pub decision: RouteDecision,
    /// Decision reason.
    pub reason: NonEmptyString,
}

/// Promotion decision between zones.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PromotionDecision {
    /// Source zone.
    pub from_zone: ZoneId,
    /// Destination zone.
    pub to_zone: ZoneId,
    /// Artifact hash promoted.
    pub artifact_hash: Sha256,
    /// Whether promotion was approved.
    pub approved: bool,
    /// Approving identity.
    pub approved_by: IdentityId,
    /// Approval timestamp.
    pub approved_at: UtcTimestamp,
    /// Optional notes.
    pub notes: Option<NonEmptyString>,
}

/// Point-in-time projection of active security state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecuritySnapshot {
    /// Capture timestamp.
    pub captured_at: UtcTimestamp,
    /// Hash of the model.
    pub model_hash: Sha256,
    /// Active zones.
    pub active_zones: Vec<ZoneId>,
    /// Enabled routes.
    pub enabled_routes: Vec<RouteId>,
    /// Pending transfers.
    pub pending_transfers: Vec<TransferIntent>,
    /// Last floor event hash.
    pub last_floor_event_hash: Sha256,
}

/// Transfer aggregate used by workflow engines.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransferAggregate {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Route identifier.
    pub route_id: RouteId,
    /// Source end.
    pub from_zone: BoundaryEnd,
    /// Destination end.
    pub to_zone: BoundaryEnd,
    /// Artifact under transfer.
    pub artifact: ArtifactDescriptor,
    /// Current workflow state.
    pub state: TransferState,
    /// Workflow history.
    pub history: Vec<TransferWorkflowEvent>,
    /// Creation timestamp.
    pub created_at: UtcTimestamp,
    /// Last update timestamp.
    pub updated_at: UtcTimestamp,
}

/// Command accepted by the transfer workflow layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "type"))]
pub enum TransferCommand {
    /// Propose a new transfer.
    ProposeTransfer {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Route identifier.
        route_id: RouteId,
        /// Source end.
        from_zone: BoundaryEnd,
        /// Destination end.
        to_zone: BoundaryEnd,
        /// Artifact descriptor.
        artifact: ArtifactDescriptor,
        /// Actor.
        actor: IdentityId,
        /// Timestamp.
        at: UtcTimestamp,
    },
    /// Start verification.
    StartVerification {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
    },
    /// Record verification.
    RecordVerification {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Whether verification passed.
        passed: bool,
        /// Verification kind applied.
        verification: VerificationKind,
        /// Optional notes.
        notes: Option<NonEmptyString>,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
    },
    /// Request human approval.
    RequestHumanApproval {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
    },
    /// Approve a transfer.
    ApproveTransfer {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Approving actor.
        actor: IdentityId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Optional reason.
        reason: Option<NonEmptyString>,
    },
    /// Reject a transfer.
    RejectTransfer {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
        /// Reason.
        reason: NonEmptyString,
    },
    /// Promote an approved artifact.
    PromoteArtifact {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
    },
    /// Archive a transfer.
    ArchiveTransfer {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Actor.
        actor: ActorRef,
        /// Timestamp.
        at: UtcTimestamp,
    },
}

/// Event emitted by the transfer workflow layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "type"))]
pub enum TransferWorkflowEvent {
    /// Transfer was proposed.
    TransferProposed {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Route identifier.
        route_id: RouteId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: IdentityId,
    },
    /// Verification started.
    VerificationStarted {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
    },
    /// Verification result was recorded.
    VerificationRecorded {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Whether verification passed.
        passed: bool,
        /// Verification kind.
        verification: VerificationKind,
        /// Optional notes.
        notes: Option<NonEmptyString>,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
    },
    /// Human approval was requested.
    HumanApprovalRequested {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
    },
    /// Transfer was approved.
    TransferApproved {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: IdentityId,
        /// Optional reason.
        reason: Option<NonEmptyString>,
    },
    /// Transfer was rejected.
    TransferRejected {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
        /// Reason.
        reason: NonEmptyString,
    },
    /// Artifact was promoted.
    ArtifactPromoted {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
    },
    /// Transfer was archived.
    TransferArchived {
        /// Transfer identifier.
        transfer_id: TransferId,
        /// Timestamp.
        at: UtcTimestamp,
        /// Actor.
        actor: ActorRef,
    },
}

/// Runtime health for a policy service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServiceHealth {
    /// Logical service identity.
    pub service_id: ServiceId,
    /// Concrete service instance.
    pub instance_id: ServiceInstanceId,
    /// Current mode.
    pub mode: ServiceMode,
    /// Check timestamp.
    pub checked_at: UtcTimestamp,
    /// Optional detail.
    pub details: Option<NonEmptyString>,
}

/// Command envelope for orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommandEnvelope {
    /// Command payload.
    pub command: TransferCommand,
    /// Trace identifier.
    pub trace_id: EventId,
    /// Receipt timestamp.
    pub received_at: UtcTimestamp,
    /// Target service.
    pub target_service: ServiceId,
}

/// Event envelope for orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EventEnvelope {
    /// Event payload.
    pub event: TransferWorkflowEvent,
    /// Trace identifier.
    pub trace_id: EventId,
    /// Emission timestamp.
    pub emitted_at: UtcTimestamp,
    /// Emitting service.
    pub emitter: ServiceId,
}

/// Command execution result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommandResult {
    /// Command was accepted and emitted events.
    Ok {
        /// New transfer state.
        new_state: TransferState,
        /// Emitted workflow events.
        emitted: Vec<TransferWorkflowEvent>,
    },
    /// Command was rejected.
    Err {
        /// Reason.
        reason: NonEmptyString,
        /// Machine-readable code.
        code: CommandResultCode,
    },
}

/// Rejection code for command execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum CommandResultCode {
    /// Route is disabled.
    RouteDisabled,
    /// Policy denied the command.
    PolicyDenied,
    /// Verification failed.
    VerificationFailed,
    /// State transition is invalid.
    InvalidTransition,
    /// Target service is unavailable.
    ServiceUnavailable,
}

/// Manifest gate for strict schema layers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LayerGate {
    /// Layer being checked.
    pub layer: LayerName,
    /// Gate status.
    pub status: LayerGateStatus,
    /// Check timestamp.
    pub checked_at: UtcTimestamp,
    /// Checker name or identity.
    pub checker: NonEmptyString,
    /// Reasons for status.
    pub reasons: Vec<NonEmptyString>,
}

/// Strict schema manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SchemaManifest {
    /// Manifest identifier.
    pub manifest_id: ManifestId,
    /// Schema version.
    pub schema_version: SemVer,
    /// Creation timestamp.
    pub created_at: UtcTimestamp,
    /// Update timestamp.
    pub updated_at: UtcTimestamp,
    /// Layer gates.
    pub layers: Vec<LayerGate>,
}

/// Header required on strict policy objects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyHeader {
    /// Policy identifier.
    pub policy_id: PolicyId,
    /// Policy category.
    pub policy_type: PolicyType,
    /// Policy version.
    pub version: SemVer,
    /// Policy status.
    pub status: PolicyStatus,
    /// Owning actor.
    pub owner_actor_id: ActorId,
    /// Creation timestamp.
    pub created_at: UtcTimestamp,
    /// Update timestamp.
    pub updated_at: UtcTimestamp,
    /// Review cadence.
    pub review_rate: ReviewRate,
    /// Next review timestamp.
    pub next_review_due: UtcTimestamp,
    /// Change ticket or provenance note.
    pub change_ticket: NonEmptyString,
}

/// Typed value envelope with required default and preferred values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValueEnvelope<T> {
    /// Required value.
    pub required: bool,
    /// Default value.
    pub default: T,
    /// Preferred value.
    pub preferred: T,
    /// Explicit allowed values.
    pub allowed_values: Vec<T>,
    /// Constraint expressions interpreted by higher layers.
    pub constraints: Vec<NonEmptyString>,
}

impl<T: PartialEq> ValueEnvelope<T> {
    /// Creates a value envelope and checks allowed-value compatibility.
    pub fn new(
        required: bool,
        default: T,
        preferred: T,
        allowed_values: Vec<T>,
        constraints: Vec<NonEmptyString>,
    ) -> GuardResult<Self> {
        if !allowed_values.is_empty()
            && (!allowed_values.contains(&default) || !allowed_values.contains(&preferred))
        {
            return Err(GuardError::Invariant {
                field: "value_envelope.allowed_values",
            });
        }
        Ok(Self {
            required,
            default,
            preferred,
            allowed_values,
            constraints,
        })
    }
}

/// Scoped environment object for policy config documents.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Environment {
    /// Environment identifier.
    pub env_id: EnvironmentId,
    /// Environment name.
    pub name: NonEmptyString,
    /// Environment purpose.
    pub purpose: NonEmptyString,
}

/// Mapping from environments to zones, routes, and mandatory policies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScopedEnvironmentMap {
    /// Policy header.
    pub header: PolicyHeader,
    /// Environments.
    pub environments: Vec<Environment>,
    /// Zones.
    pub zones: Vec<ZoneId>,
    /// Routes.
    pub routes: Vec<RouteId>,
    /// Mandatory policy bindings.
    pub mandatory_policies_by_zone: Vec<ZonePolicyRequirement>,
}

/// Required policy attached to a zone.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ZonePolicyRequirement {
    /// Zone identifier.
    pub zone_id: ZoneId,
    /// Policy identifier.
    pub policy_id: PolicyId,
}

/// Policy enforcer declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyEnforcer {
    /// Enforcer identifier.
    pub id: EnforcerId,
    /// Owning identity.
    pub owner_identity: IdentityId,
    /// Failure behavior.
    pub fail_mode: FailMode,
    /// Whether this enforcer emits audit events.
    pub emits_audit: bool,
}

/// Declared policy for an outside-world edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExternalEdgePolicy {
    /// Edge identifier.
    pub id: EdgeId,
    /// Source zone.
    pub source: ZoneId,
    /// Destination class.
    pub destination_class: OutsideWorldClass,
    /// Protocol.
    pub protocol: ExternalProtocol,
    /// Ports.
    pub ports: NonEmptyVec<Port>,
    /// Default action.
    pub default_action: DefaultAction,
    /// Required enforcers.
    pub required_enforcers: NonEmptyVec<EnforcerId>,
    /// Whether audit is required.
    pub audit_required: bool,
}

/// Governance exception registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExceptionRegistration {
    /// Policy header.
    pub header: PolicyHeader,
    /// Exception identifier.
    pub exception_id: ExceptionId,
    /// Policy being excepted.
    pub policy_id: PolicyId,
    /// Environment scope.
    pub scope_env: EnvironmentId,
    /// Zone scope.
    pub scope_zone: ZoneId,
    /// Rationale.
    pub rationale: NonEmptyString,
    /// Approving actors.
    pub approved_by: NonEmptyVec<ActorId>,
    /// Start timestamp.
    pub start_at: UtcTimestamp,
    /// Expiration timestamp.
    pub expires_at: UtcTimestamp,
    /// Whether use of the exception must alert.
    pub alert_on_use: ValueEnvelope<bool>,
    /// Severity of the exception.
    pub severity: Severity,
}
