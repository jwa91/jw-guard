use alloc::{vec, vec::Vec};

use crate::{
    composites::{ArtifactContract, BoundarySpec, Policy, SecurityModel, TrustRequirement},
    concept_feedback::{run_core_concept_feedback_loop, ConceptLayer},
    enums::{
        Cadence, Capability, CredentialMechanism, CredentialStrength, FailMode, GateVerdict,
        IdentityKind, IsolationMechanism, LayerHardness, LayerMechanism, SurfaceFacing,
        TrustBasis, TrustLevel, VerificationKind, ZoneKind,
    },
    id::{
        ActorId, BoundaryId, CredentialId, EdgeId, EvaluationId, EvidenceSourceId, GateId,
        IdentityId, LayerId, ObservationId, PolicyId, ReferentId, RequirementId, RouteId, ScopeId,
        SurfaceId, TrustId, ZoneId,
    },
    scalars::{
        AbsolutePath, DisplayName, GateSequence, MediaType, NonEmptyString, NonEmptyVec, Port,
        SemVer, UtcTimestamp, ZonePurpose,
    },
    structs::{
        Boundary, BoundaryEnd, Credential, CredentialBinding, CredentialLifecycle, Gate, Layer,
        CredentialMaterial, DeclarationMetadata, Identity, Route, RouteEndpoints, Scope, Surface,
        Trust, TrustGrant, TrustParties, Zone,
    },
    theory::{
        ActorDeclaration, ActorRole, BoundaryDeclaration, Edge, EdgeDeclaration, EdgeSort,
        EvaluationContextDeclaration, EvaluationDeclaration, EvaluationResult,
        EvidenceBasis, EvidenceItem, EvidenceSourceDeclaration, EdgeToPredicateDeclaration,
        MembershipPredicateDeclaration, ModelDeclaration,
        ObservationDeclaration, PolicyDeclaration, PresenceOperator, ReferentDeclaration,
        ReferentSort, RequirementDeclaration, RequirementOperator, RequirementSort, Referent,
        SideDeclaration, SideLabel, SurfaceDeclaration, TypedScopeDeclaration, TypedValue,
    },
    theory_validation::{
        validate_core_theory_library, CoreTheoryLibrary, TheorySubject, TheoryViolationCode,
    },
    validation::{
        summarize_violation_classifications, validate_security_model, ValidationSubject, Violation,
        ViolationClassification, ViolationCode, ViolationClassificationCounts, ViolationSeverity,
    },
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

fn layer_id(byte: u8) -> LayerId {
    LayerId::from_bytes([byte; 16])
}

fn gate_id(byte: u8) -> GateId {
    GateId::from_bytes([byte; 16])
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
fn violation_code_classifies_neutral_invariant() {
    assert_eq!(
        ViolationCode::DuplicateId.classification(),
        ViolationClassification::NeutralCoreInvariant
    );
}

#[test]
fn violation_code_classifies_policy_profile_invariant() {
    assert_eq!(
        ViolationCode::GateMissingVerification.classification(),
        ViolationClassification::PolicyProfileInvariant
    );
}

#[test]
fn violation_summary_counts_by_classification() {
    let violations = vec![
        Violation {
            severity: ViolationSeverity::Error,
            code: ViolationCode::DuplicateId,
            subject: ValidationSubject::Model,
        },
        Violation {
            severity: ViolationSeverity::Warning,
            code: ViolationCode::BoundarySpecUnprotected,
            subject: ValidationSubject::Model,
        },
        Violation {
            severity: ViolationSeverity::Error,
            code: ViolationCode::MissingReference,
            subject: ValidationSubject::Model,
        },
    ];

    assert_eq!(
        summarize_violation_classifications(&violations),
        ViolationClassificationCounts {
            neutral_core_invariant: 2,
            policy_profile_invariant: 1,
        }
    );
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
fn model_validation_allows_non_airlock_signing_route_with_required_verification() {
    let signing_zone = zone(
        1,
        ZoneKind::Signing,
        TrustLevel::Critical,
        IsolationMechanism::Physical,
        "/zones/signing",
    );
    let release_zone = zone(
        2,
        ZoneKind::Release,
        TrustLevel::Standard,
        IsolationMechanism::UserAccount,
        "/zones/release",
    );
    let boundary = boundary_spec(
        1,
        BoundaryEnd::Zone(signing_zone.id),
        BoundaryEnd::Zone(release_zone.id),
    );
    let route = Route::new(
        route_id(2),
        RouteEndpoints::new(
            BoundaryEnd::Zone(signing_zone.id),
            BoundaryEnd::Zone(release_zone.id),
        )
        .unwrap(),
        boundary.boundary.id,
        Cadence::Push,
        true,
        DeclarationMetadata {
            declared_at: timestamp(),
            declared_by: identity_id(1),
        },
    )
    .unwrap();
    let gate = Gate {
        id: gate_id(1),
        route_id: route.id,
        sequence: GateSequence::new(1).unwrap(),
        required_verifications: NonEmptyVec::from_item(VerificationKind::SignatureValidity),
        verdict: GateVerdict::Pending,
    };
    let policy = Policy {
        id: PolicyId::from_bytes([1; 16]),
        route_id: route.id,
        contract: ArtifactContract::new(
            NonEmptyVec::from_item(MediaType::new("application/octet-stream").unwrap()),
            Vec::new(),
            crate::composites::IntegrityRequirement::Hash,
            None,
        ),
        gates: NonEmptyVec::from_item(gate),
        required_trust: NonEmptyVec::from_item(TrustRequirement {
            role: IdentityKind::Service,
            minimum_credential: CredentialStrength::PrimarySoftware,
            required_capabilities: NonEmptyVec::from_item(Capability::RouteExecuteTransfer),
        }),
        status: crate::enums::PolicyStatus::Active,
        version: SemVer::new("1.0.0").unwrap(),
        declared_at: timestamp(),
        declared_by: identity_id(1),
    };
    let mut secured_boundary = boundary.clone();
    secured_boundary.layers.push(Layer {
        id: layer_id(1),
        boundary_id: boundary.boundary.id,
        mechanism: LayerMechanism::Hypervisor,
        hardness: LayerHardness::H4,
        fail_mode: FailMode::FailClosed,
        enforced: true,
        verified_at: Some(timestamp()),
    });
    let declarer = Identity::new(
        identity_id(1),
        IdentityKind::Service,
        DisplayName::new("Route declarer").unwrap(),
        Some(signing_zone.id),
        false,
        timestamp(),
    )
    .unwrap();

    let mut model = empty_model();
    model.zones = vec![signing_zone, release_zone];
    model.boundary_specs = vec![secured_boundary];
    model.routes = vec![route];
    model.policies = vec![policy];
    model.identities = vec![declarer];

    let violations = validate_security_model(&model);

    assert!(!has_violation(
        &violations,
        ViolationCode::GateMissingVerification,
        ValidationSubject::Gate(gate_id(1)),
    ));
    assert!(violations.is_empty());
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

#[test]
fn concept_feedback_loop_progress_score_reports_all_pass() {
    let report = run_core_concept_feedback_loop();
    let score = report.progress_score();

    assert_eq!(score.passed_stages, 6);
    assert_eq!(score.total_stages, 6);
    assert_eq!(score.completion_ratio, 100);
    assert_eq!(score.first_failed_stage, None);
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
            evidence_basis: EvidenceBasis::from_references(NonEmptyVec::from_item(observation_id))
                .unwrap(),
            result: EvaluationResult::Unknown,
        }],
    }
}

#[test]
fn foundational_referent_and_edge_types_construct_coherently() {
    let from = Referent {
        id: ReferentId::from_bytes([70u8; 16]),
        sort: ReferentSort::Actor,
    };
    let to = Referent {
        id: ReferentId::from_bytes([71u8; 16]),
        sort: ReferentSort::Boundary,
    };

    let edge = Edge::new(
        EdgeId::from_bytes([72u8; 16]),
        EdgeSort::DependsOn,
        from.id,
        to.id,
    )
    .unwrap();

    assert_eq!(edge.from, from.id);
    assert_eq!(edge.to, to.id);
}

#[test]
fn evidence_basis_rejects_duplicate_references() {
    let observation = ObservationId::from_bytes([73u8; 16]);
    let result = EvidenceBasis::new(
        NonEmptyVec::new(vec![observation, observation], "references").unwrap(),
        Vec::new(),
    );
    assert!(result.is_err());
}

#[test]
fn evidence_item_and_observation_alias_match_shape() {
    let item = EvidenceItem {
        id: ObservationId::from_bytes([74u8; 16]),
        source: EvidenceSourceId::from_bytes([75u8; 16]),
        observed_referent: Some(ReferentId::from_bytes([76u8; 16])),
        observed_sort: ReferentSort::ReleaseArtifact,
        at: timestamp(),
        claim: TypedValue::Bool(true),
    };
    let observation: ObservationDeclaration = item.clone();

    assert_eq!(observation.id, item.id);
    assert_eq!(observation.source, item.source);
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

#[test]
fn core_theory_validation_rejects_model_declared_by_missing_actor() {
    let mut library = sample_core_theory_library();
    library.model.declared_by = ActorId::from_bytes([99u8; 16]);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::MissingReference
            && violation.subject == TheorySubject::Model
    }));
}

#[test]
fn core_theory_validation_rejects_boundary_with_missing_anchor_referent() {
    let mut library = sample_core_theory_library();
    library.boundaries[0].side_a.anchor = ReferentId::from_bytes([99u8; 16]);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::MissingReference
            && violation.subject == TheorySubject::Boundary(library.boundaries[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_scope_context_version_mismatch() {
    let mut library = sample_core_theory_library();
    library.scopes[0].context.model_version = SemVer::new("9.9.9").unwrap();

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Scope(library.scopes[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_edge_to_predicate_with_missing_referent() {
    let mut library = sample_core_theory_library();
    library.scopes[0].predicate = MembershipPredicateDeclaration::EdgeTo(EdgeToPredicateDeclaration {
        source_sort: library.scopes[0].referent_sort.clone(),
        edge_sort: EdgeSort::CrossesBoundary,
        to: ReferentId::from_bytes([88u8; 16]),
    });

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::MissingReference
            && violation.subject == TheorySubject::Scope(library.scopes[0].id)
    }));
}

#[test]
fn core_theory_validation_accepts_edge_to_with_typed_source_edges() {
    let mut library = sample_core_theory_library();
    let actor_referent = ReferentId::from_bytes([87u8; 16]);
    let target_referent = library.referents[1].id;
    library.referents.push(ReferentDeclaration {
        id: actor_referent,
        sort: ReferentSort::Actor,
    });
    library.edges.push(
        EdgeDeclaration::new(
            EdgeId::from_bytes([86u8; 16]),
            EdgeSort::DependsOn,
            actor_referent,
            target_referent,
        )
        .unwrap(),
    );
    library.scopes[0].referent_sort = ReferentSort::Actor;
    library.scopes[0].predicate = MembershipPredicateDeclaration::EdgeTo(EdgeToPredicateDeclaration {
        source_sort: ReferentSort::Actor,
        edge_sort: EdgeSort::DependsOn,
        to: target_referent,
    });

    let violations = validate_core_theory_library(&library);

    assert!(!violations.iter().any(|violation| {
        violation.subject == TheorySubject::Scope(library.scopes[0].id)
            && (violation.code == TheoryViolationCode::ScopeSortMismatch
                || violation.code == TheoryViolationCode::MissingReference)
    }));
}

#[test]
fn core_theory_validation_rejects_edge_to_with_mismatched_source_sort() {
    let mut library = sample_core_theory_library();
    library.scopes[0].referent_sort = ReferentSort::Actor;
    library.scopes[0].predicate = MembershipPredicateDeclaration::EdgeTo(EdgeToPredicateDeclaration {
        source_sort: ReferentSort::Actor,
        edge_sort: EdgeSort::CrossesBoundary,
        to: library.referents[1].id,
    });

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ScopeSortMismatch
            && violation.subject == TheorySubject::Scope(library.scopes[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_edge_to_without_matching_edge_relation() {
    let mut library = sample_core_theory_library();
    library.scopes[0].referent_sort = ReferentSort::Boundary;
    library.scopes[0].predicate = MembershipPredicateDeclaration::EdgeTo(EdgeToPredicateDeclaration {
        source_sort: ReferentSort::Boundary,
        edge_sort: EdgeSort::DependsOn,
        to: library.referents[1].id,
    });

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::MissingReference
            && violation.subject == TheorySubject::Scope(library.scopes[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_requirement_operator_value_mismatch() {
    let mut library = sample_core_theory_library();
    library.requirements[0].operator = RequirementOperator::Presence(PresenceOperator::Required);
    library.requirements[0].value = TypedValue::U64(1);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Requirement(library.requirements[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_requirement_sort_operator_mismatch() {
    let mut library = sample_core_theory_library();
    library.requirements[0].sort = RequirementSort::Count;
    library.requirements[0].operator = RequirementOperator::Presence(PresenceOperator::Required);
    library.requirements[0].value = TypedValue::Bool(true);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Requirement(library.requirements[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_edge_to_scope_source_sort_invariant_bypass() {
    let mut library = sample_core_theory_library();
    library.scopes[0].referent_sort = ReferentSort::Actor;
    library.scopes[0].predicate = MembershipPredicateDeclaration::EdgeTo(EdgeToPredicateDeclaration {
        source_sort: ReferentSort::Boundary,
        edge_sort: EdgeSort::CrossesBoundary,
        to: library.referents[1].id,
    });

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Scope(library.scopes[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_boundary_side_label_invariant_bypass() {
    let mut library = sample_core_theory_library();
    library.boundaries[0].side_a.label = SideLabel::B;

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Boundary(library.boundaries[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_boundary_surface_label_invariant_bypass() {
    let mut library = sample_core_theory_library();
    library.boundaries[0].surface_a.facing = SideLabel::B;

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Boundary(library.boundaries[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_boundary_surface_boundary_link_invariant_bypass() {
    let mut library = sample_core_theory_library();
    library.boundaries[0].surface_a.boundary_id = BoundaryId::from_bytes([98u8; 16]);

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Boundary(library.boundaries[0].id)
    }));
}

#[test]
fn core_theory_validation_rejects_boundary_distinct_anchor_invariant_bypass() {
    let mut library = sample_core_theory_library();
    library.boundaries[0].side_b.anchor = library.boundaries[0].side_a.anchor;

    let violations = validate_core_theory_library(&library);

    assert!(violations.iter().any(|violation| {
        violation.code == TheoryViolationCode::ContextInvariant
            && violation.subject == TheorySubject::Boundary(library.boundaries[0].id)
    }));
}

#[test]
fn typed_scope_new_rejects_edge_to_source_sort_mismatch() {
    let scope_id = ScopeId::from_bytes([91u8; 16]);
    let edge_to = EdgeToPredicateDeclaration {
        source_sort: ReferentSort::Actor,
        edge_sort: EdgeSort::DependsOn,
        to: ReferentId::from_bytes([92u8; 16]),
    };

    let result = TypedScopeDeclaration::new(
        scope_id,
        ReferentSort::Boundary,
        EvaluationContextDeclaration {
            model_version: SemVer::new("1.0.0").unwrap(),
            namespace: None,
            boundary: None,
            actor_authority: None,
            snapshot_at: None,
            evidence_source: None,
        },
        MembershipPredicateDeclaration::EdgeTo(edge_to),
    );

    assert!(result.is_err());
}

#[test]
fn typed_scope_edge_to_constructor_uses_edge_to_source_sort() {
    let scope_id = ScopeId::from_bytes([93u8; 16]);
    let edge_to = EdgeToPredicateDeclaration {
        source_sort: ReferentSort::ProcessEvent,
        edge_sort: EdgeSort::LogsTo,
        to: ReferentId::from_bytes([94u8; 16]),
    };

    let scope = TypedScopeDeclaration::edge_to(
        scope_id,
        EvaluationContextDeclaration {
            model_version: SemVer::new("1.0.0").unwrap(),
            namespace: None,
            boundary: None,
            actor_authority: None,
            snapshot_at: None,
            evidence_source: None,
        },
        edge_to.clone(),
    );

    assert_eq!(scope.referent_sort, edge_to.source_sort);
    assert_eq!(scope.predicate, MembershipPredicateDeclaration::EdgeTo(edge_to));
}
