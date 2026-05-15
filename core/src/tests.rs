use alloc::{vec, vec::Vec};

use crate::{
    composites::{ArtifactContract, BoundarySpec, SecurityModel},
    concept_feedback::{run_core_concept_feedback_loop, ConceptLayer},
    enums::{
        Cadence, Capability, CredentialMechanism, CredentialStrength, FailMode, IdentityKind,
        IsolationMechanism, SurfaceFacing, TrustBasis, TrustLevel, ZoneKind,
    },
    id::{
        ActorId, BoundaryId, CredentialId, EdgeId, EvaluationId, EvidenceSourceId, IdentityId,
        ObservationId, PolicyId, ReferentId, RequirementId, RouteId, ScopeId, SurfaceId, TrustId,
        ZoneId,
    },
    scalars::{
        AbsolutePath, DisplayName, MediaType, NonEmptyString, NonEmptyVec, Port, SemVer,
        UtcTimestamp, ZonePurpose,
    },
    structs::{
        Boundary, BoundaryEnd, Credential, CredentialBinding, CredentialLifecycle,
        CredentialMaterial, DeclarationMetadata, Identity, Route, RouteEndpoints, Scope, Surface,
        Trust, TrustGrant, TrustParties, Zone,
    },
    theory::{
        ActorDeclaration, ActorRole, BoundaryDeclaration, EdgeDeclaration, EdgeSort,
        EvaluationContextDeclaration, EvaluationDeclaration, EvaluationResult,
        EvidenceSourceDeclaration, MembershipPredicateDeclaration, ModelDeclaration,
        ObservationDeclaration, PolicyDeclaration, PresenceOperator, ReferentDeclaration,
        ReferentSort, RequirementDeclaration, RequirementOperator, RequirementSort, SideDeclaration,
        SideLabel, SurfaceDeclaration, TypedScopeDeclaration, TypedValue,
    },
    theory_validation::{
        validate_core_theory_library, CoreTheoryLibrary, TheorySubject, TheoryViolationCode,
    },
    validation::{validate_security_model, ValidationSubject, Violation, ViolationCode},
};

fn zone_id(byte: u8) -> ZoneId {
    ZoneId::from_bytes([byte; 16])
}

fn boundary_id(byte: u8) -> BoundaryId {
    BoundaryId::from_bytes([byte; 16])
}

fn surface_id(byte: u8) -> SurfaceId {
    SurfaceId::from_bytes([byte; 16])
}

fn route_id(byte: u8) -> RouteId {
    RouteId::from_bytes([byte; 16])
}

fn identity_id(byte: u8) -> IdentityId {
    IdentityId::from_bytes([byte; 16])
}

fn scope_id(byte: u8) -> ScopeId {
    ScopeId::from_bytes([byte; 16])
}

fn credential_id(byte: u8) -> CredentialId {
    CredentialId::from_bytes([byte; 16])
}

fn trust_id(byte: u8) -> TrustId {
    TrustId::from_bytes([byte; 16])
}

fn timestamp() -> UtcTimestamp {
    UtcTimestamp::new("2026-05-15T00:00:00Z").unwrap()
}

fn empty_model() -> SecurityModel {
    SecurityModel {
        model_version: SemVer::new("0.1.0").unwrap(),
        zones: Vec::new(),
        boundary_specs: Vec::new(),
        routes: Vec::new(),
        policies: Vec::new(),
        identities: Vec::new(),
        scopes: Vec::new(),
        credentials: Vec::new(),
        trusts: Vec::new(),
    }
}

fn zone(
    byte: u8,
    kind: ZoneKind,
    trust_level: TrustLevel,
    isolation: IsolationMechanism,
    root: &str,
) -> Zone {
    Zone::new(
        zone_id(byte),
        kind,
        ZonePurpose::new("test zone").unwrap(),
        trust_level,
        isolation,
        NonEmptyVec::new(vec![AbsolutePath::new(root).unwrap()], "filesystem_roots").unwrap(),
        timestamp(),
    )
    .unwrap()
}

fn boundary_spec(byte: u8, side_a: BoundaryEnd, side_b: BoundaryEnd) -> BoundarySpec {
    let boundary = Boundary::new(boundary_id(byte), side_a, side_b).unwrap();
    let surface_a = Surface {
        id: surface_id(byte),
        boundary_id: boundary.id,
        facing: SurfaceFacing::A,
        exposed_paths: Vec::new(),
        exposed_listeners: Vec::new(),
        exposed_capabilities: Vec::new(),
    };
    let surface_b = Surface {
        id: surface_id(byte + 1),
        boundary_id: boundary.id,
        facing: SurfaceFacing::B,
        exposed_paths: Vec::new(),
        exposed_listeners: Vec::new(),
        exposed_capabilities: Vec::new(),
    };
    BoundarySpec::new(boundary, Vec::new(), [surface_a, surface_b])
}

fn scope(id: ScopeId, zone_id: ZoneId, capability: Capability) -> Scope {
    Scope {
        id,
        zone_id,
        capabilities: NonEmptyVec::from_item(capability),
        constraints: Vec::new(),
    }
}

fn has_violation(
    violations: &[Violation],
    code: ViolationCode,
    subject: ValidationSubject,
) -> bool {
    violations
        .iter()
        .any(|violation| violation.code == code && violation.subject == subject)
}

#[test]
fn port_zero_is_rejected() {
    assert!(Port::new(0).is_err());
    assert_eq!(Port::new(443).unwrap().get(), 443);
}

#[test]
fn signature_contract_requires_hash() {
    let media_types =
        NonEmptyVec::new(vec![MediaType::new("application/json").unwrap()], "media").unwrap();

    assert!(ArtifactContract::from_flags(media_types, Vec::new(), false, true, None).is_err());
}

#[test]
fn boundary_spec_computes_empty_posture() {
    let boundary = Boundary::new(
        boundary_id(10),
        BoundaryEnd::Zone(zone_id(1)),
        BoundaryEnd::Zone(zone_id(2)),
    )
    .unwrap();
    let surface_a = Surface {
        id: surface_id(1),
        boundary_id: boundary.id,
        facing: SurfaceFacing::A,
        exposed_paths: Vec::new(),
        exposed_listeners: Vec::new(),
        exposed_capabilities: Vec::new(),
    };
    let surface_b = Surface {
        id: surface_id(2),
        boundary_id: boundary.id,
        facing: SurfaceFacing::B,
        exposed_paths: Vec::new(),
        exposed_listeners: Vec::new(),
        exposed_capabilities: Vec::new(),
    };

    let spec = BoundarySpec::new(boundary, Vec::new(), [surface_a, surface_b]);

    assert_eq!(spec.effective_hardness(), None);
    assert_eq!(spec.effective_fail_mode(), FailMode::FailOpen);
}

#[test]
fn model_validation_detects_overlapping_zone_roots() {
    let zone_a = Zone::new(
        zone_id(1),
        ZoneKind::Dev,
        ZonePurpose::new("source authoring").unwrap(),
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        NonEmptyVec::new(
            vec![AbsolutePath::new("/Users/dev-admin").unwrap()],
            "filesystem_roots",
        )
        .unwrap(),
        timestamp(),
    )
    .unwrap();
    let zone_b = Zone::new(
        zone_id(2),
        ZoneKind::Build,
        ZonePurpose::new("build execution").unwrap(),
        TrustLevel::High,
        IsolationMechanism::Vm,
        NonEmptyVec::new(
            vec![AbsolutePath::new("/Users/dev-admin/project").unwrap()],
            "filesystem_roots",
        )
        .unwrap(),
        timestamp(),
    )
    .unwrap();
    let model = SecurityModel {
        model_version: SemVer::new("0.1.0").unwrap(),
        zones: vec![zone_a, zone_b],
        boundary_specs: Vec::new(),
        routes: Vec::new(),
        policies: Vec::new(),
        identities: Vec::new(),
        scopes: Vec::new(),
        credentials: Vec::new(),
        trusts: Vec::new(),
    };

    let violations = validate_security_model(&model);

    assert!(violations
        .iter()
        .any(|violation| violation.code == ViolationCode::FilesystemRootOverlap));
}

#[test]
fn model_validation_detects_duplicate_scope_ids() {
    let dev_zone = zone(
        1,
        ZoneKind::Dev,
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        "/zones/dev",
    );
    let duplicate_id = scope_id(1);
    let mut model = empty_model();
    model.zones = vec![dev_zone.clone()];
    model.scopes = vec![
        scope(duplicate_id, dev_zone.id, Capability::FsRead),
        scope(duplicate_id, dev_zone.id, Capability::FsWrite),
    ];

    let violations = validate_security_model(&model);

    assert!(has_violation(
        &violations,
        ViolationCode::DuplicateId,
        ValidationSubject::Scope(duplicate_id),
    ));
}

#[test]
fn model_validation_detects_missing_route_declarer() {
    let dev_zone = zone(
        1,
        ZoneKind::Dev,
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        "/zones/dev",
    );
    let build_zone = zone(
        2,
        ZoneKind::Build,
        TrustLevel::Low,
        IsolationMechanism::Container,
        "/zones/build",
    );
    let boundary = boundary_spec(
        1,
        BoundaryEnd::Zone(dev_zone.id),
        BoundaryEnd::Zone(build_zone.id),
    );
    let route = Route::new(
        route_id(1),
        RouteEndpoints::new(
            BoundaryEnd::Zone(dev_zone.id),
            BoundaryEnd::Zone(build_zone.id),
        )
        .unwrap(),
        boundary.boundary.id,
        Cadence::Push,
        true,
        DeclarationMetadata {
            declared_at: timestamp(),
            declared_by: identity_id(99),
        },
    )
    .unwrap();
    let mut model = empty_model();
    model.zones = vec![dev_zone, build_zone];
    model.boundary_specs = vec![boundary];
    model.routes = vec![route];

    let violations = validate_security_model(&model);

    assert!(has_violation(
        &violations,
        ViolationCode::MissingReference,
        ValidationSubject::Route(route_id(1)),
    ));
}

#[test]
fn model_validation_detects_trust_grant_without_authority() {
    let dev_zone = zone(
        1,
        ZoneKind::Dev,
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        "/zones/dev",
    );
    let admin = Identity::new(
        identity_id(1),
        IdentityKind::ZoneAdmin,
        DisplayName::new("Dev admin").unwrap(),
        Some(dev_zone.id),
        false,
        timestamp(),
    )
    .unwrap();
    let service = Identity::new(
        identity_id(2),
        IdentityKind::Service,
        DisplayName::new("Build service").unwrap(),
        Some(dev_zone.id),
        false,
        timestamp(),
    )
    .unwrap();
    let read_scope = scope(scope_id(1), dev_zone.id, Capability::FsRead);
    let trust = Trust::new(
        trust_id(1),
        TrustParties {
            identity_id: service.id,
            scope_id: read_scope.id,
            granted_by: admin.id,
        },
        TrustGrant {
            basis: TrustBasis::RoleAssignment,
            granted_at: timestamp(),
            expires_at: None,
            requires_credential: CredentialStrength::PrimarySoftware,
            active: true,
        },
    )
    .unwrap();
    let mut model = empty_model();
    model.zones = vec![dev_zone];
    model.identities = vec![admin, service];
    model.scopes = vec![read_scope];
    model.trusts = vec![trust];

    let violations = validate_security_model(&model);

    assert!(has_violation(
        &violations,
        ViolationCode::TrustGrantAuthorityMissing,
        ValidationSubject::Trust(trust_id(1)),
    ));
}

#[test]
fn model_validation_rejects_multiple_root_bootstrap_self_grants() {
    let identity_zone = zone(
        1,
        ZoneKind::Identity,
        TrustLevel::Critical,
        IsolationMechanism::Physical,
        "/zones/identity",
    );
    let root = Identity::new(
        identity_id(1),
        IdentityKind::Root,
        DisplayName::new("Root").unwrap(),
        None,
        false,
        timestamp(),
    )
    .unwrap();
    let credential = Credential::new(
        credential_id(1),
        CredentialBinding {
            identity_id: root.id,
            stored_in: identity_zone.id,
        },
        CredentialMaterial {
            mechanism: CredentialMechanism::PasswordOffline,
            strength: CredentialStrength::PrimaryHardware,
            fingerprint: None,
        },
        CredentialLifecycle {
            expires_at: None,
            rotated_at: timestamp(),
        },
    )
    .unwrap();
    let root_scope = scope(scope_id(1), identity_zone.id, Capability::ZoneDeclare);
    let first_bootstrap = Trust::new(
        trust_id(1),
        TrustParties {
            identity_id: root.id,
            scope_id: root_scope.id,
            granted_by: root.id,
        },
        TrustGrant {
            basis: TrustBasis::SystemBootstrap,
            granted_at: timestamp(),
            expires_at: None,
            requires_credential: CredentialStrength::PrimaryHardware,
            active: true,
        },
    )
    .unwrap();
    let second_bootstrap = Trust::new(
        trust_id(2),
        TrustParties {
            identity_id: root.id,
            scope_id: root_scope.id,
            granted_by: root.id,
        },
        TrustGrant {
            basis: TrustBasis::SystemBootstrap,
            granted_at: timestamp(),
            expires_at: None,
            requires_credential: CredentialStrength::PrimaryHardware,
            active: true,
        },
    )
    .unwrap();
    let mut model = empty_model();
    model.zones = vec![identity_zone];
    model.identities = vec![root];
    model.scopes = vec![root_scope];
    model.credentials = vec![credential];
    model.trusts = vec![first_bootstrap, second_bootstrap];

    let violations = validate_security_model(&model);

    assert!(has_violation(
        &violations,
        ViolationCode::TrustInvariant,
        ValidationSubject::Trust(trust_id(2)),
    ));
}

#[cfg(feature = "serde")]
#[test]
fn serde_deserialization_enforces_scalar_invariants() {
    assert!(serde_json::from_str::<Port>("0").is_err());
    assert!(serde_json::from_str::<MediaType>("\"not-a-media-type\"").is_err());
    assert!(serde_json::from_str::<NonEmptyVec<MediaType>>("[]").is_err());
}

#[test]
fn concept_feedback_loop_passes_primitive_layer_before_advancing() {
    let report = run_core_concept_feedback_loop();
    assert!(!report.layers.is_empty());
    assert_eq!(report.layers[0].layer, ConceptLayer::PrimitiveDatatypes);
    assert!(report.layers[0].passed());
}

#[test]
fn concept_feedback_loop_reaches_top_layer_when_core_atoms_exist() {
    let report = run_core_concept_feedback_loop();
    assert_eq!(report.halted_at, None);
    assert_eq!(report.layers.len(), 6);
    assert!(report.passed_all());
    assert!(report
        .layers
        .iter()
        .all(|layer| layer.layer >= ConceptLayer::PrimitiveDatatypes && layer.passed()));
}

fn sample_core_theory_library() -> CoreTheoryLibrary {
    let actor_id = ActorId::from_bytes([1u8; 16]);
    let boundary_referent = ReferentId::from_bytes([2u8; 16]);
    let artifact_referent = ReferentId::from_bytes([3u8; 16]);
    let boundary_id = BoundaryId::from_bytes([4u8; 16]);
    let scope_id = ScopeId::from_bytes([5u8; 16]);
    let requirement_id = RequirementId::from_bytes([6u8; 16]);
    let policy_id = PolicyId::from_bytes([7u8; 16]);
    let source_id = EvidenceSourceId::from_bytes([8u8; 16]);
    let observation_id = ObservationId::from_bytes([9u8; 16]);
    let evaluation_id = EvaluationId::from_bytes([10u8; 16]);

    CoreTheoryLibrary {
        model: ModelDeclaration {
            id: crate::id::ModelId::from_bytes([11u8; 16]),
            version: SemVer::new("1.0.0").unwrap(),
            declared_at: timestamp(),
            declared_by: actor_id,
        },
        actors: vec![ActorDeclaration {
            id: actor_id,
            role: ActorRole::System,
        }],
        referents: vec![
            ReferentDeclaration {
                id: boundary_referent,
                sort: ReferentSort::Boundary,
            },
            ReferentDeclaration {
                id: artifact_referent,
                sort: ReferentSort::ReleaseArtifact,
            },
        ],
        boundaries: vec![
            BoundaryDeclaration::new(
                boundary_id,
                SideDeclaration {
                    label: SideLabel::A,
                    anchor: boundary_referent,
                },
                SideDeclaration {
                    label: SideLabel::B,
                    anchor: artifact_referent,
                },
                SurfaceDeclaration {
                    id: SurfaceId::from_bytes([12u8; 16]),
                    boundary_id,
                    facing: SideLabel::A,
                },
                SurfaceDeclaration {
                    id: SurfaceId::from_bytes([13u8; 16]),
                    boundary_id,
                    facing: SideLabel::B,
                },
            )
            .unwrap(),
        ],
        edges: vec![
            EdgeDeclaration::new(
                EdgeId::from_bytes([14u8; 16]),
                EdgeSort::CrossesBoundary,
                boundary_referent,
                artifact_referent,
            )
            .unwrap(),
        ],
        scopes: vec![TypedScopeDeclaration {
            id: scope_id,
            referent_sort: ReferentSort::ReleaseArtifact,
            context: EvaluationContextDeclaration {
                model_version: SemVer::new("1.0.0").unwrap(),
                namespace: None,
                boundary: None,
                actor_authority: None,
                snapshot_at: None,
                evidence_source: None,
            },
            predicate: MembershipPredicateDeclaration::ReferentIds {
                ids: NonEmptyVec::from_item(artifact_referent),
            },
        }],
        requirements: vec![
            RequirementDeclaration::new(
                requirement_id,
                RequirementSort::Presence,
                RequirementOperator::Presence(PresenceOperator::Required),
                TypedValue::Bool(true),
            )
            .unwrap(),
        ],
        policies: vec![PolicyDeclaration {
            id: policy_id,
            declared_by: actor_id,
            scope: scope_id,
            requirement: requirement_id,
        }],
        evidence_sources: vec![EvidenceSourceDeclaration {
            id: source_id,
            source_type: NonEmptyString::new("scanner").unwrap(),
            mapper: NonEmptyString::new("mapper-v1").unwrap(),
            trust_assumption: NonEmptyString::new("signed feed").unwrap(),
        }],
        observations: vec![ObservationDeclaration {
            id: observation_id,
            source: source_id,
            observed_referent: Some(artifact_referent),
            observed_sort: ReferentSort::ReleaseArtifact,
            at: timestamp(),
            claim: TypedValue::Bool(true),
        }],
        evaluations: vec![EvaluationDeclaration {
            id: evaluation_id,
            policy: policy_id,
            evidence_basis: NonEmptyVec::from_item(observation_id),
            result: EvaluationResult::Unknown,
        }],
    }
}

#[test]
fn core_theory_validation_accepts_minimal_coherent_library() {
    let library = sample_core_theory_library();
    let violations = validate_core_theory_library(&library);
    assert!(violations.is_empty());
}

#[test]
fn core_theory_validation_rejects_policy_missing_requirement_reference() {
    let mut library = sample_core_theory_library();
    library.policies[0].requirement = RequirementId::from_bytes([99u8; 16]);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::MissingReference
            && violation.subject == TheorySubject::Policy(library.policies[0].id)
    }));
}
