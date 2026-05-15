use crate::{
    composites::{ArtifactContract, BoundarySpec, SecurityModel},
    enums::{FailMode, IsolationMechanism, SurfaceFacing, TrustLevel, ZoneKind},
    id::{BoundaryId, SurfaceId, ZoneId},
    scalars::{AbsolutePath, MediaType, NonEmptyVec, Port, SemVer, UtcTimestamp, ZonePurpose},
    structs::{Boundary, BoundaryEnd, Surface, Zone},
    validation::{validate_security_model, ViolationCode},
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

fn timestamp() -> UtcTimestamp {
    UtcTimestamp::new("2026-05-15T00:00:00Z").unwrap()
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

#[cfg(feature = "serde")]
#[test]
fn serde_deserialization_enforces_scalar_invariants() {
    assert!(serde_json::from_str::<Port>("0").is_err());
    assert!(serde_json::from_str::<MediaType>("\"not-a-media-type\"").is_err());
    assert!(serde_json::from_str::<NonEmptyVec<MediaType>>("[]").is_err());
}
