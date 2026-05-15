use alloc::{vec, vec::Vec};

use jw_guard_core::{
    enums::{
        Cadence, Capability, FailMode, IsolationMechanism, LayerHardness, LayerMechanism,
        TrustLevel, ZoneKind,
    },
    scalars::{AbsolutePath, NonEmptyVec, SemVer, ZonePurpose},
};

use crate::{
    declaration::{
        BoundaryDeclaration, BoundaryEndRef, LayerRequirement, RouteDeclaration, ScopeDeclaration,
        SecurityDeclaration, ZoneDeclaration,
    },
    name::DeclarationName,
    requirement::{PresenceRequirement, StrengthRequirement},
    scope::{ScopeKind, ScopeTarget},
    validation::{
        validate_security_declaration, DeclarationSubject, DeclarationViolation,
        DeclarationViolationCode,
    },
};

fn name(value: &str) -> DeclarationName {
    DeclarationName::new(value).unwrap()
}

fn zone(
    value: &str,
    kind: ZoneKind,
    trust_level: TrustLevel,
    isolation: IsolationMechanism,
    root: &str,
) -> ZoneDeclaration {
    ZoneDeclaration {
        name: name(value),
        label: None,
        kind,
        purpose: ZonePurpose::new("test zone").unwrap(),
        trust_level,
        isolation,
        filesystem_roots: NonEmptyVec::new(
            vec![AbsolutePath::new(root).unwrap()],
            "filesystem_roots",
        )
        .unwrap(),
    }
}

fn declaration() -> SecurityDeclaration {
    SecurityDeclaration {
        declaration_version: SemVer::new("0.1.0").unwrap(),
        zones: Vec::new(),
        boundaries: Vec::new(),
        scopes: Vec::new(),
        routes: Vec::new(),
        route_policies: Vec::new(),
    }
}

fn boundary(value: &str, side_a: BoundaryEndRef, side_b: BoundaryEndRef) -> BoundaryDeclaration {
    BoundaryDeclaration {
        name: name(value),
        side_a,
        side_b,
        layer_requirements: vec![LayerRequirement {
            mechanism: LayerMechanism::UserSeparation,
            presence: PresenceRequirement::Required,
            hardness: Some(StrengthRequirement::AtLeast(LayerHardness::H2)),
            fail_mode: Some(FailMode::FailClosed),
        }],
    }
}

fn route(
    value: &str,
    from: BoundaryEndRef,
    to: BoundaryEndRef,
    boundary: &str,
) -> RouteDeclaration {
    RouteDeclaration {
        name: name(value),
        presence: PresenceRequirement::Required,
        from,
        to,
        boundary: name(boundary),
        cadence: Cadence::Push,
        enabled: true,
    }
}

fn has_violation(
    violations: &[DeclarationViolation],
    code: DeclarationViolationCode,
    subject: DeclarationSubject,
) -> bool {
    violations
        .iter()
        .any(|violation| violation.code == code && violation.subject == subject)
}

#[test]
fn declaration_validation_accepts_precise_minimum_shape() {
    let mut declaration = declaration();
    declaration.zones = vec![
        zone(
            "dev",
            ZoneKind::Dev,
            TrustLevel::Standard,
            IsolationMechanism::UserAccount,
            "/zones/dev",
        ),
        zone(
            "build",
            ZoneKind::Build,
            TrustLevel::Low,
            IsolationMechanism::Container,
            "/zones/build",
        ),
    ];
    declaration.boundaries = vec![boundary(
        "dev-build",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Zone(name("build")),
    )];
    declaration.routes = vec![route(
        "source",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Zone(name("build")),
        "dev-build",
    )];
    declaration.scopes = vec![ScopeDeclaration {
        name: name("dev-files"),
        kind: ScopeKind::Filesystem,
        target: ScopeTarget::Zone(name("dev")),
        required_capabilities: NonEmptyVec::from_item(Capability::FsRead),
        forbidden_capabilities: vec![Capability::FsWrite],
    }];

    let violations = validate_security_declaration(&declaration);

    assert!(violations.is_empty());
}

#[test]
fn declaration_validation_rejects_impossible_layer_requirement() {
    let mut declaration = declaration();
    declaration.zones = vec![
        zone(
            "dev",
            ZoneKind::Dev,
            TrustLevel::Standard,
            IsolationMechanism::UserAccount,
            "/zones/dev",
        ),
        zone(
            "build",
            ZoneKind::Build,
            TrustLevel::Low,
            IsolationMechanism::Container,
            "/zones/build",
        ),
    ];
    declaration.boundaries = vec![BoundaryDeclaration {
        name: name("dev-build"),
        side_a: BoundaryEndRef::Zone(name("dev")),
        side_b: BoundaryEndRef::Zone(name("build")),
        layer_requirements: vec![LayerRequirement {
            mechanism: LayerMechanism::PacketFilter,
            presence: PresenceRequirement::Required,
            hardness: Some(StrengthRequirement::AtLeast(LayerHardness::H4)),
            fail_mode: Some(FailMode::FailClosed),
        }],
    }];

    let violations = validate_security_declaration(&declaration);

    assert!(has_violation(
        &violations,
        DeclarationViolationCode::ImpossibleLayerRequirement,
        DeclarationSubject::LayerRequirement {
            boundary: name("dev-build"),
            mechanism: LayerMechanism::PacketFilter,
        },
    ));
}

#[test]
fn declaration_validation_rejects_scope_target_mismatch() {
    let mut declaration = declaration();
    declaration.zones = vec![
        zone(
            "dev",
            ZoneKind::Dev,
            TrustLevel::Standard,
            IsolationMechanism::UserAccount,
            "/zones/dev",
        ),
        zone(
            "build",
            ZoneKind::Build,
            TrustLevel::Low,
            IsolationMechanism::Container,
            "/zones/build",
        ),
    ];
    declaration.boundaries = vec![boundary(
        "dev-build",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Zone(name("build")),
    )];
    declaration.routes = vec![route(
        "source",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Zone(name("build")),
        "dev-build",
    )];
    declaration.scopes = vec![ScopeDeclaration {
        name: name("source-files"),
        kind: ScopeKind::Filesystem,
        target: ScopeTarget::Route(name("source")),
        required_capabilities: NonEmptyVec::from_item(Capability::FsRead),
        forbidden_capabilities: Vec::new(),
    }];

    let violations = validate_security_declaration(&declaration);

    assert!(has_violation(
        &violations,
        DeclarationViolationCode::ScopeTargetMismatch,
        DeclarationSubject::Scope(name("source-files")),
    ));
}

#[test]
fn declaration_validation_rejects_route_boundary_mismatch() {
    let mut declaration = declaration();
    declaration.zones = vec![
        zone(
            "dev",
            ZoneKind::Dev,
            TrustLevel::Standard,
            IsolationMechanism::UserAccount,
            "/zones/dev",
        ),
        zone(
            "build",
            ZoneKind::Build,
            TrustLevel::Low,
            IsolationMechanism::Container,
            "/zones/build",
        ),
    ];
    declaration.boundaries = vec![boundary(
        "dev-build",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Zone(name("build")),
    )];
    declaration.routes = vec![route(
        "dev-public",
        BoundaryEndRef::Zone(name("dev")),
        BoundaryEndRef::Outside,
        "dev-build",
    )];

    let violations = validate_security_declaration(&declaration);

    assert!(has_violation(
        &violations,
        DeclarationViolationCode::RouteBoundaryMismatch,
        DeclarationSubject::Route(name("dev-public")),
    ));
}

#[test]
fn declaration_validation_rejects_capability_contradiction() {
    let mut declaration = declaration();
    declaration.zones = vec![zone(
        "dev",
        ZoneKind::Dev,
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        "/zones/dev",
    )];
    declaration.scopes = vec![ScopeDeclaration {
        name: name("dev-files"),
        kind: ScopeKind::Filesystem,
        target: ScopeTarget::Zone(name("dev")),
        required_capabilities: NonEmptyVec::from_item(Capability::FsRead),
        forbidden_capabilities: vec![Capability::FsRead],
    }];

    let violations = validate_security_declaration(&declaration);

    assert!(has_violation(
        &violations,
        DeclarationViolationCode::CapabilityContradiction,
        DeclarationSubject::Scope(name("dev-files")),
    ));
}

#[test]
fn declaration_validation_does_not_imply_airlock_for_signing_routes() {
    let mut declaration = declaration();
    declaration.zones = vec![
        zone(
            "signing",
            ZoneKind::Signing,
            TrustLevel::High,
            IsolationMechanism::Vm,
            "/zones/signing",
        ),
        zone(
            "build",
            ZoneKind::Build,
            TrustLevel::Standard,
            IsolationMechanism::Container,
            "/zones/build",
        ),
    ];
    declaration.boundaries = vec![boundary(
        "signing-build",
        BoundaryEndRef::Zone(name("signing")),
        BoundaryEndRef::Zone(name("build")),
    )];
    declaration.routes = vec![route(
        "build-signing",
        BoundaryEndRef::Zone(name("build")),
        BoundaryEndRef::Zone(name("signing")),
        "signing-build",
    )];

    let violations = validate_security_declaration(&declaration);

    assert!(violations.is_empty());
}
