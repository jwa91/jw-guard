use alloc::{vec, vec::Vec};

use jw_guard_core::{
    composites::{ArtifactContract, TrustRequirement},
    enums::{
        Cadence, Capability, CredentialStrength, FailMode, IdentityKind, IsolationMechanism,
        LayerHardness, LayerMechanism, VerificationKind, TrustLevel, ZoneKind,
    },
    scalars::{AbsolutePath, GateSequence, MediaType, NonEmptyVec, SemVer, UtcTimestamp, ZonePurpose},
};

use crate::{
    concretise::{
        build_canonical_model, derive_deterministic_id, normalize_security_declaration,
        run_concretisation_loop, ConcretisationStage, DeterministicIdKind,
    },
    declaration::{
        BoundaryDeclaration, BoundaryEndRef, GateRequirement, LayerRequirement, RouteDeclaration,
        RoutePolicyDeclaration, ScopeDeclaration, SecurityDeclaration, ZoneDeclaration,
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

fn declaration_with_policy() -> SecurityDeclaration {
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
        name: name("source"),
        kind: ScopeKind::ArtifactFlow,
        target: ScopeTarget::Route(name("source")),
        required_capabilities: NonEmptyVec::from_item(Capability::RouteExecuteTransfer),
        forbidden_capabilities: vec![Capability::RouteApproveTransfer],
    }];
    declaration.route_policies = vec![RoutePolicyDeclaration {
        name: name("source-policy"),
        route: name("source"),
        contract: ArtifactContract::new(
            NonEmptyVec::from_item(MediaType::new("application/json").unwrap()),
            Vec::new(),
            jw_guard_core::composites::IntegrityRequirement::Hash,
            None,
        ),
        gates: NonEmptyVec::from_item(GateRequirement {
            sequence: GateSequence::new(1).unwrap(),
            required_verifications: NonEmptyVec::from_item(VerificationKind::HashIntegrity),
        }),
        required_trust: NonEmptyVec::from_item(TrustRequirement {
            role: IdentityKind::Service,
            minimum_credential: CredentialStrength::PrimarySoftware,
            required_capabilities: NonEmptyVec::from_item(Capability::RouteExecuteTransfer),
        }),
        declared_at: UtcTimestamp::new("2026-05-15T00:00:00Z").unwrap(),
    }];
    declaration
}

#[test]
fn deterministic_id_derivation_is_repeatable() {
    let schema = SemVer::new("1.0.0").unwrap();
    let path = "boundary/dev-build";
    let left = derive_deterministic_id(DeterministicIdKind::Boundary, &schema, path);
    let right = derive_deterministic_id(DeterministicIdKind::Boundary, &schema, path);
    assert_eq!(left, right);
}

#[test]
fn normalization_is_permutation_invariant() {
    let left = declaration_with_policy();
    let mut right = declaration_with_policy();
    right.zones.reverse();
    right.boundaries.reverse();
    right.scopes.reverse();
    right.routes.reverse();
    right.route_policies.reverse();

    let normalized_left = normalize_security_declaration(&left);
    let normalized_right = normalize_security_declaration(&right);

    assert_eq!(normalized_left, normalized_right);
}

#[test]
fn concretisation_loop_passes_on_coherent_declaration() {
    let declaration = declaration_with_policy();
    let report = run_concretisation_loop(&declaration);
    assert!(report.passed(), "{report:#?}");
    assert_eq!(report.halted_at, None);
    assert_eq!(
        report
            .stages
            .iter()
            .filter(|stage| stage.passed)
            .count(),
        6
    );
    assert!(report
        .stages
        .iter()
        .any(|stage| stage.stage == ConcretisationStage::ValidateCanonicalTheoryGraph));
}

#[test]
fn canonical_model_is_stable_across_input_permutations() {
    let left = declaration_with_policy();
    let mut right = declaration_with_policy();
    right.zones.reverse();
    right.boundaries.reverse();
    right.scopes.reverse();
    right.routes.reverse();
    right.route_policies.reverse();

    let canonical_left = build_canonical_model(normalize_security_declaration(&left));
    let canonical_right = build_canonical_model(normalize_security_declaration(&right));

    assert_eq!(canonical_left.paths, canonical_right.paths);
    assert_eq!(canonical_left.theory, canonical_right.theory);
}
