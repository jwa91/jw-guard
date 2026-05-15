use alloc::{collections::BTreeSet, vec::Vec};

use jw_guard_core::{
    enums::{IsolationMechanism, LayerMechanism, TrustLevel, ZoneKind},
    scalars::AbsolutePath,
};

use crate::{
    declaration::{
        BoundaryDeclaration, BoundaryEndRef, LayerRequirement, RouteDeclaration,
        RoutePolicyDeclaration, ScopeDeclaration, SecurityDeclaration, ZoneDeclaration,
    },
    name::DeclarationName,
    requirement::PresenceRequirement,
    scope::ScopeTarget,
};

/// Severity of a declaration validation result.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeclarationSeverity {
    /// Declaration can still be interpreted, but intent is under-specified.
    Warning,
    /// Declaration is internally inconsistent or ambiguous.
    Error,
}

/// Machine-readable declaration validation code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum DeclarationViolationCode {
    /// A symbolic declaration name is duplicated in its namespace.
    DuplicateName,
    /// A declaration references an object that does not exist.
    MissingReference,
    /// Zone declaration violates zone-specific static rules.
    ZoneInvariant,
    /// Filesystem roots overlap across declared zones.
    FilesystemRootOverlap,
    /// Boundary connects the same side to itself.
    BoundarySelfConnection,
    /// Boundary connects outside to outside.
    BoundaryOutsideOnly,
    /// Boundary side order does not follow declared trust order.
    BoundaryTrustOrder,
    /// More than one boundary declares the same pair of ends.
    DuplicateBoundaryPair,
    /// Boundary declares no protection-layer requirement.
    BoundaryWithoutLayerRequirement,
    /// A required layer does not state a hardness requirement.
    RequiredLayerMissingHardness,
    /// A forbidden layer also declares hardness or fail-mode constraints.
    ForbiddenLayerHasControls,
    /// A layer hardness requirement cannot be satisfied by that mechanism.
    ImpossibleLayerRequirement,
    /// Route endpoints do not match the declared boundary.
    RouteBoundaryMismatch,
    /// A policy is attached to a route declared forbidden.
    PolicyOnForbiddenRoute,
    /// Policy gate sequence is not strictly increasing.
    GateSequenceInvariant,
    /// Scope kind is not meaningful for its target type.
    ScopeTargetMismatch,
    /// Scope requires and forbids the same capability.
    CapabilityContradiction,
}

/// Declaration object a validation result refers to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DeclarationSubject {
    /// Whole declaration.
    Declaration,
    /// Zone declaration.
    Zone(DeclarationName),
    /// Boundary declaration.
    Boundary(DeclarationName),
    /// Layer requirement on a boundary.
    LayerRequirement {
        /// Boundary name.
        boundary: DeclarationName,
        /// Mechanism being constrained.
        mechanism: LayerMechanism,
    },
    /// Scope declaration.
    Scope(DeclarationName),
    /// Route declaration.
    Route(DeclarationName),
    /// Route policy declaration.
    RoutePolicy(DeclarationName),
}

/// Pure declaration validation result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeclarationViolation {
    /// Warning or error.
    pub severity: DeclarationSeverity,
    /// Machine-readable code.
    pub code: DeclarationViolationCode,
    /// Subject that failed validation.
    pub subject: DeclarationSubject,
}

impl DeclarationViolation {
    fn error(code: DeclarationViolationCode, subject: DeclarationSubject) -> Self {
        Self {
            severity: DeclarationSeverity::Error,
            code,
            subject,
        }
    }

    fn warning(code: DeclarationViolationCode, subject: DeclarationSubject) -> Self {
        Self {
            severity: DeclarationSeverity::Warning,
            code,
            subject,
        }
    }
}

/// Validates declaration-local precision before lowering to core ids.
pub fn validate_security_declaration(
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    violations.extend(validate_unique_zone_names(&declaration.zones));
    violations.extend(validate_unique_boundary_names(&declaration.boundaries));
    violations.extend(validate_unique_scope_names(&declaration.scopes));
    violations.extend(validate_unique_route_names(&declaration.routes));
    violations.extend(validate_unique_policy_names(&declaration.route_policies));
    violations.extend(validate_declared_filesystem_roots(&declaration.zones));

    for zone in &declaration.zones {
        violations.extend(validate_zone_declaration(zone));
    }
    for boundary in &declaration.boundaries {
        violations.extend(validate_boundary_declaration(boundary, declaration));
    }
    violations.extend(validate_unique_boundary_pairs(&declaration.boundaries));
    for scope in &declaration.scopes {
        violations.extend(validate_scope_declaration(scope, declaration));
    }
    for route in &declaration.routes {
        violations.extend(validate_route_declaration(route, declaration));
    }
    for policy in &declaration.route_policies {
        violations.extend(validate_route_policy_declaration(policy, declaration));
    }
    violations
}

impl SecurityDeclaration {
    /// Validates declaration-local precision before lowering to core ids.
    pub fn validate(&self) -> Vec<DeclarationViolation> {
        validate_security_declaration(self)
    }
}

fn validate_unique_zone_names(zones: &[ZoneDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for zone in zones {
        if !seen.insert(zone.name.clone()) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateName,
                DeclarationSubject::Zone(zone.name.clone()),
            ));
        }
    }
    violations
}

fn validate_unique_boundary_names(boundaries: &[BoundaryDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for boundary in boundaries {
        if !seen.insert(boundary.name.clone()) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateName,
                DeclarationSubject::Boundary(boundary.name.clone()),
            ));
        }
    }
    violations
}

fn validate_unique_scope_names(scopes: &[ScopeDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for scope in scopes {
        if !seen.insert(scope.name.clone()) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateName,
                DeclarationSubject::Scope(scope.name.clone()),
            ));
        }
    }
    violations
}

fn validate_unique_route_names(routes: &[RouteDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for route in routes {
        if !seen.insert(route.name.clone()) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateName,
                DeclarationSubject::Route(route.name.clone()),
            ));
        }
    }
    violations
}

fn validate_unique_policy_names(policies: &[RoutePolicyDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for policy in policies {
        if !seen.insert(policy.name.clone()) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateName,
                DeclarationSubject::RoutePolicy(policy.name.clone()),
            ));
        }
    }
    violations
}

fn validate_zone_declaration(zone: &ZoneDeclaration) -> Vec<DeclarationViolation> {
    let invalid = matches!(zone.kind, ZoneKind::Signing)
        && !matches!(
            zone.isolation,
            IsolationMechanism::Vm | IsolationMechanism::Physical
        )
        || matches!(zone.kind, ZoneKind::Quarantine) && zone.trust_level != TrustLevel::Untrusted;

    if invalid {
        alloc::vec![DeclarationViolation::error(
            DeclarationViolationCode::ZoneInvariant,
            DeclarationSubject::Zone(zone.name.clone()),
        )]
    } else {
        Vec::new()
    }
}

fn validate_declared_filesystem_roots(zones: &[ZoneDeclaration]) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    for (left_idx, left) in zones.iter().enumerate() {
        for right in zones.iter().skip(left_idx + 1) {
            for left_path in left.filesystem_roots.as_slice() {
                for right_path in right.filesystem_roots.as_slice() {
                    if paths_overlap(left_path, right_path) {
                        violations.push(DeclarationViolation::error(
                            DeclarationViolationCode::FilesystemRootOverlap,
                            DeclarationSubject::Zone(right.name.clone()),
                        ));
                    }
                }
            }
        }
    }
    violations
}

fn validate_boundary_declaration(
    boundary: &BoundaryDeclaration,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    if boundary.side_a == boundary.side_b {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::BoundarySelfConnection,
            DeclarationSubject::Boundary(boundary.name.clone()),
        ));
    }
    if matches!(
        (&boundary.side_a, &boundary.side_b),
        (BoundaryEndRef::Outside, BoundaryEndRef::Outside)
    ) {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::BoundaryOutsideOnly,
            DeclarationSubject::Boundary(boundary.name.clone()),
        ));
    }
    violations.extend(validate_boundary_end_reference(
        &boundary.side_a,
        DeclarationSubject::Boundary(boundary.name.clone()),
        declaration,
    ));
    violations.extend(validate_boundary_end_reference(
        &boundary.side_b,
        DeclarationSubject::Boundary(boundary.name.clone()),
        declaration,
    ));
    if boundary_has_inverted_trust_order(boundary, declaration) {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::BoundaryTrustOrder,
            DeclarationSubject::Boundary(boundary.name.clone()),
        ));
    }
    if boundary.layer_requirements.is_empty() {
        violations.push(DeclarationViolation::warning(
            DeclarationViolationCode::BoundaryWithoutLayerRequirement,
            DeclarationSubject::Boundary(boundary.name.clone()),
        ));
    }
    for requirement in &boundary.layer_requirements {
        violations.extend(validate_layer_requirement(&boundary.name, requirement));
    }
    violations
}

fn validate_unique_boundary_pairs(boundaries: &[BoundaryDeclaration]) -> Vec<DeclarationViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for boundary in boundaries {
        let pair = canonical_pair(&boundary.side_a, &boundary.side_b);
        if !seen.insert(pair) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::DuplicateBoundaryPair,
                DeclarationSubject::Boundary(boundary.name.clone()),
            ));
        }
    }
    violations
}

fn validate_layer_requirement(
    boundary: &DeclarationName,
    requirement: &LayerRequirement,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    let subject = DeclarationSubject::LayerRequirement {
        boundary: boundary.clone(),
        mechanism: requirement.mechanism,
    };

    match requirement.presence {
        PresenceRequirement::Required if requirement.hardness.is_none() => {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::RequiredLayerMissingHardness,
                subject.clone(),
            ));
        }
        PresenceRequirement::Forbidden
            if requirement.hardness.is_some() || requirement.fail_mode.is_some() =>
        {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::ForbiddenLayerHasControls,
                subject.clone(),
            ));
        }
        _ => {}
    }

    if let Some(hardness) = requirement.hardness {
        let (minimum, maximum) = requirement.mechanism.hardness_range();
        if !hardness.is_satisfiable_within(minimum, maximum) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::ImpossibleLayerRequirement,
                subject,
            ));
        }
    }
    violations
}

fn validate_scope_declaration(
    scope: &ScopeDeclaration,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    if !scope.kind.accepts_target(&scope.target) {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::ScopeTargetMismatch,
            DeclarationSubject::Scope(scope.name.clone()),
        ));
    }
    violations.extend(validate_scope_target_reference(
        &scope.target,
        DeclarationSubject::Scope(scope.name.clone()),
        declaration,
    ));
    for capability in scope.required_capabilities.as_slice() {
        if scope.forbidden_capabilities.contains(capability) {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::CapabilityContradiction,
                DeclarationSubject::Scope(scope.name.clone()),
            ));
        }
    }
    violations
}

fn validate_route_declaration(
    route: &RouteDeclaration,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    if route.from == route.to {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::BoundarySelfConnection,
            DeclarationSubject::Route(route.name.clone()),
        ));
    }
    if matches!(
        (&route.from, &route.to),
        (BoundaryEndRef::Outside, BoundaryEndRef::Outside)
    ) {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::BoundaryOutsideOnly,
            DeclarationSubject::Route(route.name.clone()),
        ));
    }
    violations.extend(validate_boundary_end_reference(
        &route.from,
        DeclarationSubject::Route(route.name.clone()),
        declaration,
    ));
    violations.extend(validate_boundary_end_reference(
        &route.to,
        DeclarationSubject::Route(route.name.clone()),
        declaration,
    ));

    let Some(boundary) = find_boundary(declaration, &route.boundary) else {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::MissingReference,
            DeclarationSubject::Route(route.name.clone()),
        ));
        return violations;
    };
    if canonical_pair(&route.from, &route.to) != canonical_pair(&boundary.side_a, &boundary.side_b)
    {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::RouteBoundaryMismatch,
            DeclarationSubject::Route(route.name.clone()),
        ));
    }
    violations
}

fn validate_route_policy_declaration(
    policy: &RoutePolicyDeclaration,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let mut violations = Vec::new();
    let Some(route) = find_route(declaration, &policy.route) else {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::MissingReference,
            DeclarationSubject::RoutePolicy(policy.name.clone()),
        ));
        return violations;
    };
    if route.presence == PresenceRequirement::Forbidden {
        violations.push(DeclarationViolation::error(
            DeclarationViolationCode::PolicyOnForbiddenRoute,
            DeclarationSubject::RoutePolicy(policy.name.clone()),
        ));
    }

    let mut last_sequence = 0;
    for gate in policy.gates.as_slice() {
        let sequence = gate.sequence.get();
        if sequence <= last_sequence {
            violations.push(DeclarationViolation::error(
                DeclarationViolationCode::GateSequenceInvariant,
                DeclarationSubject::RoutePolicy(policy.name.clone()),
            ));
        }
        last_sequence = sequence;
    }
    violations
}

fn validate_boundary_end_reference(
    end: &BoundaryEndRef,
    subject: DeclarationSubject,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    match end {
        BoundaryEndRef::Zone(name) if find_zone(declaration, name).is_none() => {
            alloc::vec![DeclarationViolation::error(
                DeclarationViolationCode::MissingReference,
                subject,
            )]
        }
        _ => Vec::new(),
    }
}

fn validate_scope_target_reference(
    target: &ScopeTarget,
    subject: DeclarationSubject,
    declaration: &SecurityDeclaration,
) -> Vec<DeclarationViolation> {
    let missing = match target {
        ScopeTarget::Zone(name) => find_zone(declaration, name).is_none(),
        ScopeTarget::Boundary(name) => find_boundary(declaration, name).is_none(),
        ScopeTarget::Route(name) => find_route(declaration, name).is_none(),
    };

    if missing {
        alloc::vec![DeclarationViolation::error(
            DeclarationViolationCode::MissingReference,
            subject,
        )]
    } else {
        Vec::new()
    }
}

fn find_zone<'a>(
    declaration: &'a SecurityDeclaration,
    name: &DeclarationName,
) -> Option<&'a ZoneDeclaration> {
    declaration.zones.iter().find(|zone| zone.name == *name)
}

fn find_boundary<'a>(
    declaration: &'a SecurityDeclaration,
    name: &DeclarationName,
) -> Option<&'a BoundaryDeclaration> {
    declaration
        .boundaries
        .iter()
        .find(|boundary| boundary.name == *name)
}

fn find_route<'a>(
    declaration: &'a SecurityDeclaration,
    name: &DeclarationName,
) -> Option<&'a RouteDeclaration> {
    declaration.routes.iter().find(|route| route.name == *name)
}

fn boundary_has_inverted_trust_order(
    boundary: &BoundaryDeclaration,
    declaration: &SecurityDeclaration,
) -> bool {
    let (BoundaryEndRef::Zone(side_a), BoundaryEndRef::Zone(side_b)) =
        (&boundary.side_a, &boundary.side_b)
    else {
        return false;
    };
    let (Some(side_a), Some(side_b)) = (
        find_zone(declaration, side_a),
        find_zone(declaration, side_b),
    ) else {
        return false;
    };
    side_a.trust_level < side_b.trust_level
}

fn canonical_pair(
    left: &BoundaryEndRef,
    right: &BoundaryEndRef,
) -> (BoundaryEndRef, BoundaryEndRef) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn paths_overlap(left: &AbsolutePath, right: &AbsolutePath) -> bool {
    path_is_prefix(left.as_str(), right.as_str()) || path_is_prefix(right.as_str(), left.as_str())
}

fn path_is_prefix(prefix: &str, path: &str) -> bool {
    prefix == path
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}
