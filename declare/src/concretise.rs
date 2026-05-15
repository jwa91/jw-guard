use alloc::{collections::BTreeMap, string::String, vec::Vec};

use jw_guard_core::{
    id::{
        ActorId, BoundaryId, EdgeId, ModelId, PolicyId, ReferentId, RequirementId, ScopeId,
        SurfaceId,
    },
    scalars::{NonEmptyString, NonEmptyVec, SemVer, UtcTimestamp},
    theory::{
        ActorDeclaration, ActorRole, BoundaryDeclaration as TheoryBoundaryDeclaration, EdgeDeclaration,
        EdgeSort, EvaluationContextDeclaration, MembershipPredicateDeclaration, ModelDeclaration,
        PolicyDeclaration, ReferentDeclaration, ReferentSort, RequirementDeclaration,
        RequirementOperator, RequirementSort, SideDeclaration, SideLabel, SurfaceDeclaration,
        TypedScopeDeclaration, TypedValue,
    },
    theory_validation::{validate_core_theory_library, CoreTheoryLibrary, TheoryViolation},
};
use sha2::{Digest, Sha256};

use crate::{
    declaration::{
        BoundaryDeclaration, BoundaryEndRef, RouteDeclaration, RoutePolicyDeclaration,
        ScopeDeclaration, SecurityDeclaration, ZoneDeclaration,
    },
    name::DeclarationName,
    validation::{validate_security_declaration, DeclarationViolation},
};

/// Ordered deterministic concretisation pipeline stage.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConcretisationStage {
    ValidateDeclaration,
    NormalizeDeclaration,
    DeriveCanonicalPaths,
    DeriveDeterministicIds,
    BuildCanonicalTheoryGraph,
    ValidateCanonicalTheoryGraph,
}

/// Failure reason for a concretisation stage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConcretisationFailure {
    DeclarationViolations(Vec<DeclarationViolation>),
    DeterministicIdCollisions(Vec<DeterministicIdCollision>),
    TheoryViolations(Vec<TheoryViolation>),
}

/// Deterministic-id collision detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeterministicIdCollision {
    pub kind: DeterministicIdKind,
    pub first_path: String,
    pub second_path: String,
}

/// One concretisation stage result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConcretisationStageResult {
    pub stage: ConcretisationStage,
    pub passed: bool,
}

/// Full concretisation report with strict fail-fast stage gating.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConcretisationReport {
    pub stages: Vec<ConcretisationStageResult>,
    pub halted_at: Option<ConcretisationStage>,
    pub failure: Option<ConcretisationFailure>,
    pub canonical_model: Option<CanonicalModel>,
}

impl ConcretisationReport {
    /// Returns true when every stage passed.
    pub fn passed(&self) -> bool {
        self.halted_at.is_none()
    }
}

/// Normalized declaration form used as canonicalization input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NormalizedSecurityDeclaration {
    pub declaration_version: SemVer,
    pub zones: Vec<ZoneDeclaration>,
    pub boundaries: Vec<BoundaryDeclaration>,
    pub scopes: Vec<ScopeDeclaration>,
    pub routes: Vec<RouteDeclaration>,
    pub route_policies: Vec<RoutePolicyDeclaration>,
}

/// Canonical path references for declaration objects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalPaths {
    pub model: String,
    pub actor_system: String,
    pub zones: Vec<(DeclarationName, String)>,
    pub boundaries: Vec<(DeclarationName, String)>,
    pub scopes: Vec<(DeclarationName, String)>,
    pub routes: Vec<(DeclarationName, String)>,
    pub policies: Vec<(DeclarationName, String)>,
    pub requirements: Vec<(DeclarationName, String)>,
    pub policy_scopes: Vec<(DeclarationName, String)>,
}

/// Deterministically-built canonical model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalModel {
    pub normalized: NormalizedSecurityDeclaration,
    pub paths: CanonicalPaths,
    pub theory: CoreTheoryLibrary,
}

/// Deterministic domain-separated id kinds.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeterministicIdKind {
    Model,
    Actor,
    Referent,
    Boundary,
    Surface,
    Edge,
    Scope,
    Requirement,
    Policy,
}

impl DeterministicIdKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Actor => "actor",
            Self::Referent => "referent",
            Self::Boundary => "boundary",
            Self::Surface => "surface",
            Self::Edge => "edge",
            Self::Scope => "scope",
            Self::Requirement => "requirement",
            Self::Policy => "policy",
        }
    }
}

/// Derives deterministic 128-bit ids from schema version and canonical path.
pub fn derive_deterministic_id(
    kind: DeterministicIdKind,
    schema_version: &SemVer,
    canonical_path: &str,
) -> [u8; 16] {
    let input = format!(
        "jw-guard:{}:{}:{}",
        kind.as_str(),
        schema_version.as_str(),
        canonical_path
    );
    let digest = Sha256::digest(input.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Normalizes declaration collections to deterministic canonical order.
pub fn normalize_security_declaration(
    declaration: &SecurityDeclaration,
) -> NormalizedSecurityDeclaration {
    let mut zones = declaration.zones.clone();
    let mut boundaries = declaration.boundaries.clone();
    let mut scopes = declaration.scopes.clone();
    let mut routes = declaration.routes.clone();
    let mut route_policies = declaration.route_policies.clone();

    zones.sort_by(|left, right| left.name.cmp(&right.name));
    boundaries.sort_by(|left, right| left.name.cmp(&right.name));
    scopes.sort_by(|left, right| left.name.cmp(&right.name));
    routes.sort_by(|left, right| left.name.cmp(&right.name));
    route_policies.sort_by(|left, right| left.name.cmp(&right.name));

    for boundary in &mut boundaries {
        boundary
            .layer_requirements
            .sort_by(|left, right| left.mechanism.cmp(&right.mechanism));
    }

    NormalizedSecurityDeclaration {
        declaration_version: declaration.declaration_version.clone(),
        zones,
        boundaries,
        scopes,
        routes,
        route_policies,
    }
}

/// Derives canonical declaration paths from normalized declaration.
pub fn derive_canonical_paths(normalized: &NormalizedSecurityDeclaration) -> CanonicalPaths {
    let model = format!("model/jw-guard/{}", normalized.declaration_version.as_str());
    let actor_system = "actor/system".to_owned();
    let zones = normalized
        .zones
        .iter()
        .map(|zone| (zone.name.clone(), format!("referent/zone/{}", zone.name.as_str())))
        .collect();
    let boundaries = normalized
        .boundaries
        .iter()
        .map(|boundary| {
            (
                boundary.name.clone(),
                format!("boundary/{}", boundary.name.as_str()),
            )
        })
        .collect();
    let scopes = normalized
        .scopes
        .iter()
        .map(|scope| (scope.name.clone(), format!("scope/{}", scope.name.as_str())))
        .collect();
    let routes = normalized
        .routes
        .iter()
        .map(|route| (route.name.clone(), format!("edge/route/{}", route.name.as_str())))
        .collect();
    let policies = normalized
        .route_policies
        .iter()
        .map(|policy| {
            (
                policy.name.clone(),
                format!("policy/{}", policy.name.as_str()),
            )
        })
        .collect();
    let requirements = normalized
        .route_policies
        .iter()
        .map(|policy| {
            (
                policy.name.clone(),
                format!("requirement/route-policy/{}", policy.name.as_str()),
            )
        })
        .collect();
    let policy_scopes = normalized
        .route_policies
        .iter()
        .map(|policy| {
            (
                policy.name.clone(),
                format!("scope/route-policy/{}", policy.name.as_str()),
            )
        })
        .collect();
    CanonicalPaths {
        model,
        actor_system,
        zones,
        boundaries,
        scopes,
        routes,
        policies,
        requirements,
        policy_scopes,
    }
}

/// Builds a canonical theory graph from normalized declarations.
pub fn build_canonical_model(normalized: NormalizedSecurityDeclaration) -> CanonicalModel {
    let paths = derive_canonical_paths(&normalized);
    let schema_version = &normalized.declaration_version;

    let model_id = ModelId::from_bytes(derive_deterministic_id(
        DeterministicIdKind::Model,
        schema_version,
        &paths.model,
    ));
    let actor_id = ActorId::from_bytes(derive_deterministic_id(
        DeterministicIdKind::Actor,
        schema_version,
        &paths.actor_system,
    ));
    let timestamp = UtcTimestamp::new("2026-01-01T00:00:00Z")
        .expect("static timestamp must remain valid");
    let model = ModelDeclaration {
        id: model_id,
        version: schema_version.clone(),
        declared_at: timestamp,
        declared_by: actor_id,
    };
    let actors = alloc::vec![ActorDeclaration {
        id: actor_id,
        role: ActorRole::System,
    }];

    let outside_path = "referent/outside/default".to_owned();
    let outside_referent_id = ReferentId::from_bytes(derive_deterministic_id(
        DeterministicIdKind::Referent,
        schema_version,
        &outside_path,
    ));

    let mut referents: Vec<ReferentDeclaration> = normalized
        .zones
        .iter()
        .map(|zone| {
            let path = zone_path(&paths, &zone.name);
            ReferentDeclaration {
                id: ReferentId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Referent,
                    schema_version,
                    path,
                )),
                sort: ReferentSort::Custom {
                    name: NonEmptyString::new("zone").expect("non-empty"),
                },
            }
        })
        .collect();
    referents.extend(normalized.boundaries.iter().map(|boundary| {
        let path = boundary_path(&paths, &boundary.name);
        ReferentDeclaration {
            id: ReferentId::from_bytes(derive_deterministic_id(
                DeterministicIdKind::Referent,
                schema_version,
                path,
            )),
            sort: ReferentSort::Boundary,
        }
    }));
    referents.extend(normalized.routes.iter().map(|route| {
        let path = route_path(&paths, &route.name);
        ReferentDeclaration {
            id: ReferentId::from_bytes(derive_deterministic_id(
                DeterministicIdKind::Referent,
                schema_version,
                path,
            )),
            sort: ReferentSort::Edge,
        }
    }));
    referents.push(ReferentDeclaration {
        id: outside_referent_id,
        sort: ReferentSort::Custom {
            name: NonEmptyString::new("outside").expect("non-empty"),
        },
    });

    let boundaries: Vec<TheoryBoundaryDeclaration> = normalized
        .boundaries
        .iter()
        .map(|boundary| {
            let path = boundary_path(&paths, &boundary.name);
            let boundary_id = BoundaryId::from_bytes(derive_deterministic_id(
                DeterministicIdKind::Boundary,
                schema_version,
                path,
            ));
            let side_a_anchor = resolve_end_referent_id(
                &boundary.side_a,
                schema_version,
                &paths,
                outside_referent_id,
            );
            let side_b_anchor = resolve_end_referent_id(
                &boundary.side_b,
                schema_version,
                &paths,
                outside_referent_id,
            );
            let surface_a = SurfaceDeclaration {
                id: SurfaceId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Surface,
                    schema_version,
                    &format!("{}/surface/a", path),
                )),
                boundary_id,
                facing: SideLabel::A,
            };
            let surface_b = SurfaceDeclaration {
                id: SurfaceId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Surface,
                    schema_version,
                    &format!("{}/surface/b", path),
                )),
                boundary_id,
                facing: SideLabel::B,
            };
            TheoryBoundaryDeclaration::new(
                boundary_id,
                SideDeclaration {
                    label: SideLabel::A,
                    anchor: side_a_anchor,
                },
                SideDeclaration {
                    label: SideLabel::B,
                    anchor: side_b_anchor,
                },
                surface_a,
                surface_b,
            )
            .expect("normalized declarations must produce coherent boundaries")
        })
        .collect();

    let edges: Vec<EdgeDeclaration> = normalized
        .routes
        .iter()
        .map(|route| {
            let path = route_path(&paths, &route.name);
            let from = resolve_end_referent_id(&route.from, schema_version, &paths, outside_referent_id);
            let to = resolve_end_referent_id(&route.to, schema_version, &paths, outside_referent_id);
            EdgeDeclaration::new(
                EdgeId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Edge,
                    schema_version,
                    path,
                )),
                EdgeSort::CrossesBoundary,
                from,
                to,
            )
            .expect("normalized route ends are validated distinct")
        })
        .collect();

    let mut scopes: Vec<TypedScopeDeclaration> = normalized
        .scopes
        .iter()
        .map(|scope| {
            let path = scope_path(&paths, &scope.name);
            let target_referent = scope_target_referent_id(
                &scope.target,
                schema_version,
                &paths,
            );
            TypedScopeDeclaration {
                id: ScopeId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Scope,
                    schema_version,
                    path,
                )),
                referent_sort: scope_target_sort(&scope.target),
                context: EvaluationContextDeclaration {
                    model_version: schema_version.clone(),
                    namespace: None,
                    boundary: None,
                    actor_authority: Some(actor_id),
                    snapshot_at: None,
                    evidence_source: None,
                },
                predicate: MembershipPredicateDeclaration::ReferentIds {
                    ids: NonEmptyVec::from_item(target_referent),
                },
            }
        })
        .collect();
    scopes.extend(normalized.route_policies.iter().map(|policy| {
        let path = policy_scope_path(&paths, &policy.name);
        let route_path = route_path(&paths, &policy.route);
        let target_referent = ReferentId::from_bytes(derive_deterministic_id(
            DeterministicIdKind::Referent,
            schema_version,
            route_path,
        ));
        TypedScopeDeclaration {
            id: ScopeId::from_bytes(derive_deterministic_id(
                DeterministicIdKind::Scope,
                schema_version,
                path,
            )),
            referent_sort: ReferentSort::Edge,
            context: EvaluationContextDeclaration {
                model_version: schema_version.clone(),
                namespace: None,
                boundary: None,
                actor_authority: Some(actor_id),
                snapshot_at: None,
                evidence_source: None,
            },
            predicate: MembershipPredicateDeclaration::ReferentIds {
                ids: NonEmptyVec::from_item(target_referent),
            },
        }
    }));

    let requirements: Vec<RequirementDeclaration> = normalized
        .route_policies
        .iter()
        .map(|policy| {
            let path = requirement_path(&paths, &policy.name);
            RequirementDeclaration::new(
                RequirementId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Requirement,
                    schema_version,
                    path,
                )),
                RequirementSort::Relation,
                RequirementOperator::Relation(jw_guard_core::theory::RelationOperator::Exists),
                TypedValue::Bool(true),
            )
            .expect("static requirement relation must be valid")
        })
        .collect();

    let policies: Vec<PolicyDeclaration> = normalized
        .route_policies
        .iter()
        .map(|policy| {
            let policy_path = policy_path(&paths, &policy.name);
            let requirement_path = requirement_path(&paths, &policy.name);
            let route_scope_path = policy_scope_path(&paths, &policy.name);
            PolicyDeclaration {
                id: PolicyId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Policy,
                    schema_version,
                    policy_path,
                )),
                declared_by: actor_id,
                scope: ScopeId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Scope,
                    schema_version,
                    route_scope_path,
                )),
                requirement: RequirementId::from_bytes(derive_deterministic_id(
                    DeterministicIdKind::Requirement,
                    schema_version,
                    requirement_path,
                )),
            }
        })
        .collect();

    let theory = CoreTheoryLibrary {
        model,
        actors,
        referents,
        boundaries,
        edges,
        scopes,
        requirements,
        policies,
        evidence_sources: Vec::new(),
        observations: Vec::new(),
        evaluations: Vec::new(),
    };

    CanonicalModel {
        normalized,
        paths,
        theory,
    }
}

/// Runs strict fail-fast concretisation loop for declarations.
pub fn run_concretisation_loop(declaration: &SecurityDeclaration) -> ConcretisationReport {
    let mut stages = Vec::new();

    let declaration_violations = validate_security_declaration(declaration);
    let declaration_passed = declaration_violations.is_empty();
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::ValidateDeclaration,
        passed: declaration_passed,
    });
    if !declaration_passed {
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::ValidateDeclaration),
            failure: Some(ConcretisationFailure::DeclarationViolations(
                declaration_violations,
            )),
            canonical_model: None,
        };
    }

    let normalized = normalize_security_declaration(declaration);
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::NormalizeDeclaration,
        passed: true,
    });

    let paths = derive_canonical_paths(&normalized);
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::DeriveCanonicalPaths,
        passed: true,
    });

    // Smoke-check deterministic id derivation with model path.
    let schema_version = &normalized.declaration_version;
    let collisions = detect_deterministic_id_collisions(&paths, schema_version);
    let ids_passed = collisions.is_empty();
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::DeriveDeterministicIds,
        passed: ids_passed,
    });
    if !ids_passed {
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::DeriveDeterministicIds),
            failure: Some(ConcretisationFailure::DeterministicIdCollisions(collisions)),
            canonical_model: None,
        };
    }

    let canonical_model = build_canonical_model(normalized);
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::BuildCanonicalTheoryGraph,
        passed: true,
    });

    let theory_violations = validate_core_theory_library(&canonical_model.theory);
    let theory_passed = theory_violations.is_empty();
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::ValidateCanonicalTheoryGraph,
        passed: theory_passed,
    });
    if !theory_passed {
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::ValidateCanonicalTheoryGraph),
            failure: Some(ConcretisationFailure::TheoryViolations(theory_violations)),
            canonical_model: Some(canonical_model),
        };
    }

    ConcretisationReport {
        stages,
        halted_at: None,
        failure: None,
        canonical_model: Some(canonical_model),
    }
}

fn detect_deterministic_id_collisions(
    paths: &CanonicalPaths,
    schema_version: &SemVer,
) -> Vec<DeterministicIdCollision> {
    let mut seen: BTreeMap<(DeterministicIdKind, [u8; 16]), String> = BTreeMap::new();
    let mut collisions = Vec::new();

    let mut record = |kind: DeterministicIdKind, path: &str| {
        let id = derive_deterministic_id(kind, schema_version, path);
        let key = (kind, id);
        if let Some(first) = seen.get(&key) {
            if first != path {
                collisions.push(DeterministicIdCollision {
                    kind,
                    first_path: first.clone(),
                    second_path: path.to_owned(),
                });
            }
        } else {
            seen.insert(key, path.to_owned());
        }
    };

    record(DeterministicIdKind::Model, &paths.model);
    record(DeterministicIdKind::Actor, &paths.actor_system);
    for (_, path) in &paths.zones {
        record(DeterministicIdKind::Referent, path);
    }
    record(DeterministicIdKind::Referent, "referent/outside/default");
    for (_, path) in &paths.boundaries {
        record(DeterministicIdKind::Boundary, path);
        record(DeterministicIdKind::Surface, &format!("{path}/surface/a"));
        record(DeterministicIdKind::Surface, &format!("{path}/surface/b"));
        record(DeterministicIdKind::Referent, path);
    }
    for (_, path) in &paths.routes {
        record(DeterministicIdKind::Edge, path);
        record(DeterministicIdKind::Referent, path);
    }
    for (_, path) in &paths.scopes {
        record(DeterministicIdKind::Scope, path);
    }
    for (_, path) in &paths.policy_scopes {
        record(DeterministicIdKind::Scope, path);
    }
    for (_, path) in &paths.policies {
        record(DeterministicIdKind::Policy, path);
    }
    for (_, path) in &paths.requirements {
        record(DeterministicIdKind::Requirement, path);
    }

    collisions
}

fn zone_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .zones
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized zones must have canonical paths")
}

fn boundary_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .boundaries
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized boundaries must have canonical paths")
}

fn scope_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .scopes
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized scopes must have canonical paths")
}

fn route_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .routes
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized routes must have canonical paths")
}

fn policy_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .policies
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized policies must have canonical paths")
}

fn requirement_path<'a>(paths: &'a CanonicalPaths, name: &DeclarationName) -> &'a str {
    paths
        .requirements
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, path)| path.as_str())
        .expect("normalized requirements must have canonical paths")
}

fn policy_scope_path<'a>(paths: &'a CanonicalPaths, policy: &DeclarationName) -> &'a str {
    paths
        .policy_scopes
        .iter()
        .find(|(candidate, _)| candidate == policy)
        .map(|(_, path)| path.as_str())
        .expect("normalized policies must have canonical policy scope paths")
}

fn resolve_end_referent_id(
    end: &BoundaryEndRef,
    schema_version: &SemVer,
    paths: &CanonicalPaths,
    outside_referent_id: ReferentId,
) -> ReferentId {
    match end {
        BoundaryEndRef::Outside => outside_referent_id,
        BoundaryEndRef::Zone(name) => ReferentId::from_bytes(derive_deterministic_id(
            DeterministicIdKind::Referent,
            schema_version,
            zone_path(paths, name),
        )),
    }
}

fn scope_target_referent_id(
    target: &crate::scope::ScopeTarget,
    schema_version: &SemVer,
    paths: &CanonicalPaths,
) -> ReferentId {
    match target {
        crate::scope::ScopeTarget::Zone(name) => ReferentId::from_bytes(derive_deterministic_id(
            DeterministicIdKind::Referent,
            schema_version,
            zone_path(paths, name),
        )),
        crate::scope::ScopeTarget::Boundary(name) => ReferentId::from_bytes(derive_deterministic_id(
            DeterministicIdKind::Referent,
            schema_version,
            boundary_path(paths, name),
        )),
        crate::scope::ScopeTarget::Route(name) => ReferentId::from_bytes(derive_deterministic_id(
            DeterministicIdKind::Referent,
            schema_version,
            route_path(paths, name),
        )),
    }
}

fn scope_target_sort(target: &crate::scope::ScopeTarget) -> ReferentSort {
    match target {
        crate::scope::ScopeTarget::Zone(_) => ReferentSort::Custom {
            name: NonEmptyString::new("zone").expect("non-empty"),
        },
        crate::scope::ScopeTarget::Boundary(_) => ReferentSort::Boundary,
        crate::scope::ScopeTarget::Route(_) => ReferentSort::Edge,
    }
}
