use alloc::{collections::BTreeSet, vec::Vec};

use crate::{
    composites::{
        AccessDecision, ArtifactContract, BoundarySpec, GateEvaluation, Policy, SecurityModel,
        TrustChain,
    },
    enums::{
        Capability, CredentialMechanism, CredentialStrength, FailMode, GateVerdict, IdentityKind,
        IsolationMechanism, LayerHardness, LayerMechanism, PolicyStatus, SurfaceFacing, TrustBasis,
        TrustLevel, ZoneKind,
    },
    id::{BoundaryId, CredentialId, IdentityId, PolicyId, RouteId, ScopeId, TrustId, ZoneId},
    scalars::AbsolutePath,
    structs::{
        Boundary, BoundaryEnd, Credential, Gate, Identity, Layer, Route, Scope, Surface, Trust,
        Zone,
    },
};

/// Severity of a validation violation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ViolationSeverity {
    /// Model can still be interpreted, but posture is weaker than intended.
    Warning,
    /// Model violates a hard invariant.
    Error,
}

/// Classifies whether a violation is neutral core typing or policy/profile opinion.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ViolationClassification {
    /// Structural/type-system invariant that is independent of policy posture.
    NeutralCoreInvariant,
    /// Policy/profile choice about desired security posture.
    PolicyProfileInvariant,
}

/// Machine-readable validation code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ViolationCode {
    /// Required non-empty sequence is empty.
    EmptyRequiredSequence,
    /// Duplicate identifier was found.
    DuplicateId,
    /// Filesystem roots overlap across zones.
    FilesystemRootOverlap,
    /// Signing zone is not VM or physically isolated.
    SigningZoneSoftIsolation,
    /// Quarantine zone is not untrusted.
    QuarantineZoneTrust,
    /// Boundary connects the same side to itself.
    BoundarySelfConnection,
    /// Boundary connects outside to outside.
    BoundaryOutsideOnly,
    /// Boundary side order does not follow trust order.
    BoundaryTrustOrder,
    /// Duplicate boundary pair was found.
    DuplicateBoundaryPair,
    /// Referenced object does not exist.
    MissingReference,
    /// Layer hardness does not match its mechanism range.
    LayerHardnessMismatch,
    /// High-trust boundary has a fail-open layer.
    HighTrustBoundaryFailOpen,
    /// Boundary spec surface order is invalid.
    BoundarySpecSurfaceOrder,
    /// Boundary spec has no layers.
    BoundarySpecUnprotected,
    /// Route endpoints do not match the referenced boundary.
    RouteBoundaryMismatch,
    /// Route has no gate in any policy.
    RouteWithoutGate,
    /// Identity violates its kind-specific invariants.
    IdentityKindInvariant,
    /// Scope violates zone-specific capability rules.
    ScopeCapabilityInvariant,
    /// Credential violates mechanism or storage rules.
    CredentialInvariant,
    /// Root identity lacks offline password credential.
    RootOfflineCredentialMissing,
    /// Trust grant violates authority or credential rules.
    TrustInvariant,
    /// Trust was granted by an identity without authority in the target zone.
    TrustGrantAuthorityMissing,
    /// Artifact contract violates hash/signature rules.
    ArtifactContractInvariant,
    /// Policy violates gate, trust, status, or route invariants.
    PolicyInvariant,
    /// Access decision verdict and reason are inconsistent.
    AccessDecisionInvariant,
    /// Trust chain shape is invalid.
    TrustChainInvariant,
}

impl ViolationCode {
    /// Returns high-level invariant classification for this violation code.
    pub const fn classification(self) -> ViolationClassification {
        match self {
            Self::EmptyRequiredSequence
            | Self::DuplicateId
            | Self::FilesystemRootOverlap
            | Self::BoundarySelfConnection
            | Self::BoundaryOutsideOnly
            | Self::BoundaryTrustOrder
            | Self::DuplicateBoundaryPair
            | Self::MissingReference
            | Self::LayerHardnessMismatch
            | Self::BoundarySpecSurfaceOrder
            | Self::RouteBoundaryMismatch
            | Self::RouteWithoutGate
            | Self::IdentityKindInvariant
            | Self::CredentialInvariant
            | Self::TrustInvariant
            | Self::ArtifactContractInvariant
            | Self::PolicyInvariant
            | Self::AccessDecisionInvariant
            | Self::TrustChainInvariant => ViolationClassification::NeutralCoreInvariant,
            Self::SigningZoneSoftIsolation
            | Self::QuarantineZoneTrust
            | Self::HighTrustBoundaryFailOpen
            | Self::BoundarySpecUnprotected
            | Self::ScopeCapabilityInvariant
            | Self::RootOfflineCredentialMissing
            | Self::TrustGrantAuthorityMissing => ViolationClassification::PolicyProfileInvariant,
        }
    }
}

/// Object a validation result refers to.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ValidationSubject {
    /// Whole model.
    Model,
    /// Zone.
    Zone(ZoneId),
    /// Boundary.
    Boundary(BoundaryId),
    /// Route.
    Route(RouteId),
    /// Gate.
    Gate(crate::id::GateId),
    /// Identity.
    Identity(IdentityId),
    /// Scope.
    Scope(ScopeId),
    /// Credential.
    Credential(CredentialId),
    /// Trust.
    Trust(TrustId),
    /// Policy.
    Policy(PolicyId),
}

/// Pure validation result.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Violation {
    /// Warning or error.
    pub severity: ViolationSeverity,
    /// Machine-readable code.
    pub code: ViolationCode,
    /// Subject that failed validation.
    pub subject: ValidationSubject,
}

/// Count summary of violations by high-level invariant class.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ViolationClassificationCounts {
    /// Neutral core-typing invariant violations.
    pub neutral_core_invariant: usize,
    /// Policy/profile invariant violations.
    pub policy_profile_invariant: usize,
}

impl Violation {
    fn error(code: ViolationCode, subject: ValidationSubject) -> Self {
        Self {
            severity: ViolationSeverity::Error,
            code,
            subject,
        }
    }

    fn warning(code: ViolationCode, subject: ValidationSubject) -> Self {
        Self {
            severity: ViolationSeverity::Warning,
            code,
            subject,
        }
    }
}

/// Summarizes violations into counts grouped by classification.
pub fn summarize_violation_classifications(
    violations: &[Violation],
) -> ViolationClassificationCounts {
    let mut counts = ViolationClassificationCounts::default();
    for violation in violations {
        match violation.code.classification() {
            ViolationClassification::NeutralCoreInvariant => counts.neutral_core_invariant += 1,
            ViolationClassification::PolicyProfileInvariant => {
                counts.policy_profile_invariant += 1;
            }
        }
    }
    counts
}

/// Validates static zone invariants.
pub fn validate_zone(zone: &Zone) -> Vec<Violation> {
    let mut violations = Vec::new();
    if zone.filesystem_roots.is_empty() {
        violations.push(Violation::error(
            ViolationCode::EmptyRequiredSequence,
            ValidationSubject::Zone(zone.id),
        ));
    }
    if matches!(zone.kind, ZoneKind::Signing)
        && !matches!(
            zone.isolation,
            IsolationMechanism::Vm | IsolationMechanism::Physical
        )
    {
        violations.push(Violation::error(
            ViolationCode::SigningZoneSoftIsolation,
            ValidationSubject::Zone(zone.id),
        ));
    }
    if matches!(zone.kind, ZoneKind::Quarantine) && zone.trust_level != TrustLevel::Untrusted {
        violations.push(Violation::error(
            ViolationCode::QuarantineZoneTrust,
            ValidationSubject::Zone(zone.id),
        ));
    }
    violations
}

/// Validates static boundary invariants.
pub fn validate_boundary(boundary: &Boundary) -> Vec<Violation> {
    let mut violations = Vec::new();
    if boundary.side_a == boundary.side_b {
        violations.push(Violation::error(
            ViolationCode::BoundarySelfConnection,
            ValidationSubject::Boundary(boundary.id),
        ));
    }
    if matches!(
        (boundary.side_a, boundary.side_b),
        (BoundaryEnd::Outside, BoundaryEnd::Outside)
    ) {
        violations.push(Violation::error(
            ViolationCode::BoundaryOutsideOnly,
            ValidationSubject::Boundary(boundary.id),
        ));
    }
    violations
}

/// Validates layer mechanism and hardness compatibility.
pub fn validate_layer(layer: &Layer) -> Vec<Violation> {
    let mut violations = Vec::new();
    let (min, max) = hardness_range(layer.mechanism);
    if layer.hardness < min || layer.hardness > max {
        violations.push(Violation::error(
            ViolationCode::LayerHardnessMismatch,
            ValidationSubject::Boundary(layer.boundary_id),
        ));
    }
    violations
}

/// Validates static route invariants.
pub fn validate_route(route: &Route) -> Vec<Violation> {
    let mut violations = Vec::new();
    if route.from_zone == route.to_zone {
        violations.push(Violation::error(
            ViolationCode::BoundarySelfConnection,
            ValidationSubject::Route(route.id),
        ));
    }
    if matches!(
        (route.from_zone, route.to_zone),
        (BoundaryEnd::Outside, BoundaryEnd::Outside)
    ) {
        violations.push(Violation::error(
            ViolationCode::BoundaryOutsideOnly,
            ValidationSubject::Route(route.id),
        ));
    }
    violations
}

/// Validates static gate invariants.
pub fn validate_gate(gate: &Gate) -> Vec<Violation> {
    let mut violations = Vec::new();
    if gate.required_verifications.is_empty() {
        violations.push(Violation::error(
            ViolationCode::EmptyRequiredSequence,
            ValidationSubject::Gate(gate.id),
        ));
    }
    violations
}

/// Validates static identity invariants.
pub fn validate_identity(identity: &Identity) -> Vec<Violation> {
    let invalid = match identity.kind {
        IdentityKind::ZoneAdmin | IdentityKind::Service => identity.bound_to_zone.is_none(),
        IdentityKind::Root => identity.bound_to_zone.is_some() || identity.can_escalate,
        IdentityKind::Auditor => false,
    } || (matches!(identity.kind, IdentityKind::ZoneAdmin) && identity.can_escalate);

    if invalid {
        alloc::vec![Violation::error(
            ViolationCode::IdentityKindInvariant,
            ValidationSubject::Identity(identity.id),
        )]
    } else {
        Vec::new()
    }
}

/// Validates scope invariants that do not require zone lookup.
pub fn validate_scope(scope: &Scope) -> Vec<Violation> {
    let mut violations = Vec::new();
    if scope.capabilities.is_empty() {
        violations.push(Violation::error(
            ViolationCode::EmptyRequiredSequence,
            ValidationSubject::Scope(scope.id),
        ));
    }
    violations
}

/// Validates credential invariants that do not require model lookup.
pub fn validate_credential(credential: &Credential) -> Vec<Violation> {
    let mut violations = Vec::new();
    if matches!(credential.mechanism, CredentialMechanism::PasswordOffline)
        && credential.strength != CredentialStrength::PrimaryHardware
    {
        violations.push(Violation::error(
            ViolationCode::CredentialInvariant,
            ValidationSubject::Credential(credential.id),
        ));
    }
    if matches!(credential.mechanism, CredentialMechanism::Biometric)
        && credential.strength != CredentialStrength::Secondary
    {
        violations.push(Violation::error(
            ViolationCode::CredentialInvariant,
            ValidationSubject::Credential(credential.id),
        ));
    }
    if matches!(credential.strength, CredentialStrength::Ephemeral)
        && credential.expires_at.is_none()
    {
        violations.push(Violation::error(
            ViolationCode::CredentialInvariant,
            ValidationSubject::Credential(credential.id),
        ));
    }
    violations
}

/// Validates trust invariants that do not require full authority lookup.
pub fn validate_trust(trust: &Trust) -> Vec<Violation> {
    let mut violations = Vec::new();
    if trust.requires_credential < CredentialStrength::PrimarySoftware {
        violations.push(Violation::error(
            ViolationCode::TrustInvariant,
            ValidationSubject::Trust(trust.id),
        ));
    }
    if trust.identity_id == trust.granted_by && trust.basis != TrustBasis::SystemBootstrap {
        violations.push(Violation::error(
            ViolationCode::TrustInvariant,
            ValidationSubject::Trust(trust.id),
        ));
    }
    violations
}

/// Validates artifact contract invariants.
pub fn validate_artifact_contract(contract: &ArtifactContract) -> Vec<Violation> {
    let mut violations = Vec::new();
    if contract.allowed_media_types.is_empty() {
        violations.push(Violation::error(
            ViolationCode::EmptyRequiredSequence,
            ValidationSubject::Model,
        ));
    }
    violations
}

/// Validates boundary spec invariants.
pub fn validate_boundary_spec(spec: &BoundarySpec) -> Vec<Violation> {
    let mut violations = Vec::new();
    violations.extend(validate_boundary(&spec.boundary));
    if spec.layers.is_empty() {
        violations.push(Violation::warning(
            ViolationCode::BoundarySpecUnprotected,
            ValidationSubject::Boundary(spec.boundary.id),
        ));
    }
    if spec.surfaces[0].facing != SurfaceFacing::A || spec.surfaces[1].facing != SurfaceFacing::B {
        violations.push(Violation::error(
            ViolationCode::BoundarySpecSurfaceOrder,
            ValidationSubject::Boundary(spec.boundary.id),
        ));
    }
    for surface in &spec.surfaces {
        if surface.boundary_id != spec.boundary.id {
            violations.push(Violation::error(
                ViolationCode::MissingReference,
                ValidationSubject::Boundary(spec.boundary.id),
            ));
        }
    }
    for layer in &spec.layers {
        violations.extend(validate_layer(layer));
        if layer.boundary_id != spec.boundary.id {
            violations.push(Violation::error(
                ViolationCode::MissingReference,
                ValidationSubject::Boundary(spec.boundary.id),
            ));
        }
    }
    violations
}

/// Validates policy invariants that are local to the policy value.
pub fn validate_policy(policy: &Policy) -> Vec<Violation> {
    let mut violations = Vec::new();
    violations.extend(validate_artifact_contract(&policy.contract));
    if policy.gates.is_empty() || policy.required_trust.is_empty() {
        violations.push(Violation::error(
            ViolationCode::EmptyRequiredSequence,
            ValidationSubject::Policy(policy.id),
        ));
    }
    let mut last = 0;
    for gate in policy.gates.as_slice() {
        violations.extend(validate_gate(gate));
        let sequence = gate.sequence.get();
        if sequence <= last {
            violations.push(Violation::error(
                ViolationCode::PolicyInvariant,
                ValidationSubject::Policy(policy.id),
            ));
        }
        last = sequence;
    }
    violations
}

/// Validates access decision invariants.
pub fn validate_access_decision(decision: &AccessDecision) -> Vec<Violation> {
    match decision {
        AccessDecision::PreGateDenial(_) => Vec::new(),
        AccessDecision::GateEvaluation(evaluation) => validate_gate_evaluation(evaluation),
    }
}

/// Validates gate evaluation invariants.
pub fn validate_gate_evaluation(evaluation: &GateEvaluation) -> Vec<Violation> {
    let invalid = match evaluation.verdict {
        GateVerdict::Deny => evaluation.reason.is_none(),
        GateVerdict::Permit => evaluation.reason.is_some(),
        GateVerdict::Pending => false,
    };
    if invalid {
        alloc::vec![Violation::error(
            ViolationCode::AccessDecisionInvariant,
            ValidationSubject::Gate(evaluation.gate_id),
        )]
    } else {
        Vec::new()
    }
}

/// Validates trust chain shape.
pub fn validate_trust_chain(chain: &TrustChain) -> Vec<Violation> {
    let mut violations = Vec::new();
    if chain.root.basis != TrustBasis::SystemBootstrap {
        violations.push(Violation::error(
            ViolationCode::TrustChainInvariant,
            ValidationSubject::Trust(chain.root.id),
        ));
    }
    if chain.links.last().unwrap_or(&chain.root) != &chain.leaf {
        violations.push(Violation::error(
            ViolationCode::TrustChainInvariant,
            ValidationSubject::Trust(chain.leaf.id),
        ));
    }
    if let Some(first) = chain.links.first() {
        if first.granted_by != chain.root.identity_id {
            violations.push(Violation::error(
                ViolationCode::TrustChainInvariant,
                ValidationSubject::Trust(first.id),
            ));
        }
    }
    for pair in chain.links.windows(2) {
        if pair[1].granted_by != pair[0].identity_id {
            violations.push(Violation::error(
                ViolationCode::TrustChainInvariant,
                ValidationSubject::Trust(pair[1].id),
            ));
        }
    }
    if chain
        .links
        .iter()
        .any(|link| !link.active || link.expires_at.is_some())
        && chain.chain_valid
    {
        violations.push(Violation::error(
            ViolationCode::TrustChainInvariant,
            ValidationSubject::Trust(chain.leaf.id),
        ));
    }
    violations
}

/// Validates model-level semantic invariants.
pub fn validate_security_model(model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    violations.extend(validate_unique_zones(&model.zones));
    violations.extend(validate_unique_identities(&model.identities));
    violations.extend(validate_unique_scopes(&model.scopes));
    violations.extend(validate_unique_credentials(&model.credentials));
    violations.extend(validate_unique_trusts(&model.trusts));
    violations.extend(validate_unique_routes(&model.routes));
    violations.extend(validate_unique_policies(&model.policies));
    violations.extend(validate_filesystem_roots(&model.zones));

    for zone in &model.zones {
        violations.extend(validate_zone(zone));
    }
    for identity in &model.identities {
        violations.extend(validate_identity(identity));
    }
    for scope in &model.scopes {
        violations.extend(validate_scope(scope));
        violations.extend(validate_scope_semantic(scope, model));
    }
    for credential in &model.credentials {
        violations.extend(validate_credential(credential));
        violations.extend(validate_credential_semantic(credential, model));
    }
    for trust in &model.trusts {
        violations.extend(validate_trust(trust));
        violations.extend(validate_trust_semantic(trust, model));
    }
    for spec in &model.boundary_specs {
        violations.extend(validate_boundary_spec(spec));
        violations.extend(validate_boundary_semantic(&spec.boundary, model));
        violations.extend(validate_boundary_layers_semantic(spec, model));
    }
    violations.extend(validate_unique_boundaries(&model.boundary_specs));
    for route in &model.routes {
        violations.extend(validate_route(route));
        violations.extend(validate_route_semantic(route, model));
    }
    for policy in &model.policies {
        violations.extend(validate_policy(policy));
        violations.extend(validate_policy_semantic(policy, model));
    }
    violations.extend(validate_root_offline_credential(model));
    violations.extend(validate_unique_root_bootstrap_self_grant(model));
    violations.extend(validate_routes_have_gates(model));
    violations
}

fn validate_unique_zones(zones: &[Zone]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for zone in zones {
        if !seen.insert(zone.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Zone(zone.id),
            ));
        }
    }
    violations
}

fn validate_unique_identities(identities: &[Identity]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for identity in identities {
        if !seen.insert(identity.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Identity(identity.id),
            ));
        }
    }
    violations
}

fn validate_unique_scopes(scopes: &[Scope]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for scope in scopes {
        if !seen.insert(scope.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Scope(scope.id),
            ));
        }
    }
    violations
}

fn validate_unique_credentials(credentials: &[Credential]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for credential in credentials {
        if !seen.insert(credential.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Credential(credential.id),
            ));
        }
    }
    violations
}

fn validate_unique_trusts(trusts: &[Trust]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for trust in trusts {
        if !seen.insert(trust.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Trust(trust.id),
            ));
        }
    }
    violations
}

fn validate_unique_routes(routes: &[Route]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for route in routes {
        if !seen.insert(route.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Route(route.id),
            ));
        }
    }
    violations
}

fn validate_unique_policies(policies: &[Policy]) -> Vec<Violation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for policy in policies {
        if !seen.insert(policy.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Policy(policy.id),
            ));
        }
    }
    violations
}

fn validate_filesystem_roots(zones: &[Zone]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (left_idx, left) in zones.iter().enumerate() {
        for right in zones.iter().skip(left_idx + 1) {
            for left_path in left.filesystem_roots.as_slice() {
                for right_path in right.filesystem_roots.as_slice() {
                    if paths_overlap(left_path, right_path) {
                        violations.push(Violation::error(
                            ViolationCode::FilesystemRootOverlap,
                            ValidationSubject::Zone(right.id),
                        ));
                    }
                }
            }
        }
    }
    violations
}

fn validate_unique_boundaries(specs: &[BoundarySpec]) -> Vec<Violation> {
    let mut seen_ids = BTreeSet::new();
    let mut seen_pairs = BTreeSet::new();
    let mut violations = Vec::new();
    for spec in specs {
        if !seen_ids.insert(spec.boundary.id) {
            violations.push(Violation::error(
                ViolationCode::DuplicateId,
                ValidationSubject::Boundary(spec.boundary.id),
            ));
        }
        let pair = canonical_pair(spec.boundary.side_a, spec.boundary.side_b);
        if !seen_pairs.insert(pair) {
            violations.push(Violation::error(
                ViolationCode::DuplicateBoundaryPair,
                ValidationSubject::Boundary(spec.boundary.id),
            ));
        }
    }
    violations
}

fn validate_boundary_semantic(boundary: &Boundary, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    if let BoundaryEnd::Zone(id) = boundary.side_a {
        if find_zone(model, id).is_none() {
            violations.push(Violation::error(
                ViolationCode::MissingReference,
                ValidationSubject::Boundary(boundary.id),
            ));
        }
    }
    if let BoundaryEnd::Zone(id) = boundary.side_b {
        if find_zone(model, id).is_none() {
            violations.push(Violation::error(
                ViolationCode::MissingReference,
                ValidationSubject::Boundary(boundary.id),
            ));
        }
    }
    if let (BoundaryEnd::Zone(a), BoundaryEnd::Zone(b)) = (boundary.side_a, boundary.side_b) {
        if let (Some(a), Some(b)) = (find_zone(model, a), find_zone(model, b)) {
            if a.trust_level < b.trust_level {
                violations.push(Violation::error(
                    ViolationCode::BoundaryTrustOrder,
                    ValidationSubject::Boundary(boundary.id),
                ));
            }
        }
    }
    violations
}

fn validate_boundary_layers_semantic(spec: &BoundarySpec, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    let high_trust = boundary_touches_high_trust(&spec.boundary, model);
    if high_trust {
        for layer in &spec.layers {
            if layer.fail_mode != FailMode::FailClosed {
                violations.push(Violation::error(
                    ViolationCode::HighTrustBoundaryFailOpen,
                    ValidationSubject::Boundary(spec.boundary.id),
                ));
            }
        }
    }
    violations
}

fn validate_route_semantic(route: &Route, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Some(boundary) = find_boundary(model, route.boundary_id) else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Route(route.id),
        ));
        return violations;
    };
    if canonical_pair(route.from_zone, route.to_zone)
        != canonical_pair(boundary.side_a, boundary.side_b)
    {
        violations.push(Violation::error(
            ViolationCode::RouteBoundaryMismatch,
            ValidationSubject::Route(route.id),
        ));
    }
    if !model
        .identities
        .iter()
        .any(|identity| identity.id == route.declared_by)
    {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Route(route.id),
        ));
    }
    violations
}

fn validate_scope_semantic(scope: &Scope, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Some(zone) = find_zone(model, scope.zone_id) else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Scope(scope.id),
        ));
        return violations;
    };
    if matches!(zone.kind, ZoneKind::Audit)
        && scope
            .capabilities
            .iter()
            .any(|capability| !capability.is_audit() && *capability != Capability::FsRead)
    {
        violations.push(Violation::error(
            ViolationCode::ScopeCapabilityInvariant,
            ValidationSubject::Scope(scope.id),
        ));
    }
    if matches!(zone.kind, ZoneKind::Signing)
        && (!scope.capabilities.contains(&Capability::CryptoSign)
            || scope.capabilities.contains(&Capability::NetConnectOutbound)
            || scope.capabilities.contains(&Capability::NetListen))
    {
        violations.push(Violation::error(
            ViolationCode::ScopeCapabilityInvariant,
            ValidationSubject::Scope(scope.id),
        ));
    }
    violations
}

fn validate_credential_semantic(credential: &Credential, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    if !model
        .identities
        .iter()
        .any(|identity| identity.id == credential.identity_id)
    {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Credential(credential.id),
        ));
    }
    let Some(stored_zone) = find_zone(model, credential.stored_in) else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Credential(credential.id),
        ));
        return violations;
    };
    if !matches!(stored_zone.kind, ZoneKind::Identity | ZoneKind::Signing) {
        violations.push(Violation::error(
            ViolationCode::CredentialInvariant,
            ValidationSubject::Credential(credential.id),
        ));
    }
    violations
}

fn validate_trust_semantic(trust: &Trust, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Some(identity) = model
        .identities
        .iter()
        .find(|identity| identity.id == trust.identity_id)
    else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Trust(trust.id),
        ));
        return violations;
    };
    let grantor = model
        .identities
        .iter()
        .find(|identity| identity.id == trust.granted_by);
    if grantor.is_none() {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Trust(trust.id),
        ));
    }
    let Some(scope) = model.scopes.iter().find(|scope| scope.id == trust.scope_id) else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Trust(trust.id),
        ));
        return violations;
    };
    if trust.identity_id == trust.granted_by
        && !(trust.basis == TrustBasis::SystemBootstrap && identity.kind == IdentityKind::Root)
    {
        violations.push(Violation::error(
            ViolationCode::TrustInvariant,
            ValidationSubject::Trust(trust.id),
        ));
    }
    if matches!(trust.basis, TrustBasis::SystemBootstrap) {
        match grantor {
            Some(grantor) if grantor.kind == IdentityKind::Root => {}
            _ => violations.push(Violation::error(
                ViolationCode::TrustInvariant,
                ValidationSubject::Trust(trust.id),
            )),
        }
    }
    if let Some(bound_zone) = identity.bound_to_zone {
        if bound_zone != scope.zone_id {
            violations.push(Violation::error(
                ViolationCode::TrustInvariant,
                ValidationSubject::Trust(trust.id),
            ));
        }
    }
    if grantor.is_some()
        && !is_root_bootstrap_self_grant(trust, identity, grantor)
        && !grantor_has_zone_trust_authority(trust.granted_by, scope.zone_id, model)
    {
        violations.push(Violation::error(
            ViolationCode::TrustGrantAuthorityMissing,
            ValidationSubject::Trust(trust.id),
        ));
    }
    violations
}

fn validate_policy_semantic(policy: &Policy, model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    let Some(route) = model
        .routes
        .iter()
        .find(|route| route.id == policy.route_id)
    else {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Policy(policy.id),
        ));
        return violations;
    };
    if policy.status == PolicyStatus::Retired && route.enabled {
        violations.push(Violation::error(
            ViolationCode::PolicyInvariant,
            ValidationSubject::Policy(policy.id),
        ));
    }
    if !model
        .identities
        .iter()
        .any(|identity| identity.id == policy.declared_by)
    {
        violations.push(Violation::error(
            ViolationCode::MissingReference,
            ValidationSubject::Policy(policy.id),
        ));
    }
    for gate in policy.gates.as_slice() {
        if gate.route_id != policy.route_id {
            violations.push(Violation::error(
                ViolationCode::PolicyInvariant,
                ValidationSubject::Policy(policy.id),
            ));
        }
    }
    violations
}

fn validate_root_offline_credential(model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    for root in model
        .identities
        .iter()
        .filter(|identity| identity.kind == IdentityKind::Root)
    {
        let has_offline = model.credentials.iter().any(|credential| {
            credential.identity_id == root.id
                && credential.mechanism == CredentialMechanism::PasswordOffline
        });
        if !has_offline {
            violations.push(Violation::error(
                ViolationCode::RootOfflineCredentialMissing,
                ValidationSubject::Identity(root.id),
            ));
        }
    }
    violations
}

fn validate_unique_root_bootstrap_self_grant(model: &SecurityModel) -> Vec<Violation> {
    let mut root_bootstraps = model.trusts.iter().filter(|trust| {
        trust.identity_id == trust.granted_by
            && trust.basis == TrustBasis::SystemBootstrap
            && model
                .identities
                .iter()
                .find(|identity| identity.id == trust.identity_id)
                .map(|identity| identity.kind == IdentityKind::Root)
                .unwrap_or(false)
    });
    let _first = root_bootstraps.next();
    let mut violations = Vec::new();
    for duplicate in root_bootstraps {
        violations.push(Violation::error(
            ViolationCode::TrustInvariant,
            ValidationSubject::Trust(duplicate.id),
        ));
    }
    violations
}

fn validate_routes_have_gates(model: &SecurityModel) -> Vec<Violation> {
    let mut violations = Vec::new();
    for route in &model.routes {
        let has_gate = model
            .policies
            .iter()
            .flat_map(|policy| policy.gates.as_slice())
            .any(|gate| gate.route_id == route.id);
        if !has_gate {
            violations.push(Violation::error(
                ViolationCode::RouteWithoutGate,
                ValidationSubject::Route(route.id),
            ));
        }
    }
    violations
}

fn is_root_bootstrap_self_grant(
    trust: &Trust,
    identity: &Identity,
    grantor: Option<&Identity>,
) -> bool {
    trust.identity_id == trust.granted_by
        && trust.basis == TrustBasis::SystemBootstrap
        && identity.kind == IdentityKind::Root
        && grantor
            .map(|grantor| grantor.kind == IdentityKind::Root)
            .unwrap_or(false)
}

fn grantor_has_zone_trust_authority(
    grantor_id: IdentityId,
    target_zone_id: ZoneId,
    model: &SecurityModel,
) -> bool {
    model.trusts.iter().any(|trust| {
        trust.identity_id == grantor_id
            && trust.active
            && model
                .scopes
                .iter()
                .find(|scope| scope.id == trust.scope_id)
                .map(|scope| {
                    scope.zone_id == target_zone_id
                        && scope.capabilities.iter().any(|capability| {
                            matches!(capability, Capability::ZoneDeclare | Capability::ZoneModify)
                        })
                })
                .unwrap_or(false)
    })
}

fn hardness_range(mechanism: LayerMechanism) -> (LayerHardness, LayerHardness) {
    mechanism.hardness_range()
}

fn paths_overlap(left: &AbsolutePath, right: &AbsolutePath) -> bool {
    path_is_prefix(left.as_str(), right.as_str()) || path_is_prefix(right.as_str(), left.as_str())
}

fn path_is_prefix(prefix: &str, path: &str) -> bool {
    prefix == path
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}

fn canonical_pair(left: BoundaryEnd, right: BoundaryEnd) -> (BoundaryEnd, BoundaryEnd) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn find_zone(model: &SecurityModel, id: ZoneId) -> Option<&Zone> {
    model.zones.iter().find(|zone| zone.id == id)
}

fn find_boundary(model: &SecurityModel, id: BoundaryId) -> Option<&Boundary> {
    model
        .boundary_specs
        .iter()
        .map(|spec| &spec.boundary)
        .find(|boundary| boundary.id == id)
}

fn boundary_touches_high_trust(boundary: &Boundary, model: &SecurityModel) -> bool {
    [boundary.side_a, boundary.side_b].iter().any(|end| {
        let BoundaryEnd::Zone(id) = end else {
            return false;
        };
        find_zone(model, *id)
            .map(|zone| matches!(zone.trust_level, TrustLevel::High | TrustLevel::Critical))
            .unwrap_or(false)
    })
}

#[allow(dead_code)]
fn _surface_refs_boundary(surface: &Surface, boundary_id: BoundaryId) -> bool {
    surface.boundary_id == boundary_id
}
