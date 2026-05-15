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

impl ConcretisationStage {
    /// Stable stage key for progress reporting.
    pub const fn stage_key(self) -> &'static str {
        match self {
            Self::ValidateDeclaration => "validate_declaration",
            Self::NormalizeDeclaration => "normalize_declaration",
            Self::DeriveCanonicalPaths => "derive_canonical_paths",
            Self::DeriveDeterministicIds => "derive_deterministic_ids",
            Self::BuildCanonicalTheoryGraph => "build_canonical_theory_graph",
            Self::ValidateCanonicalTheoryGraph => "validate_canonical_theory_graph",
        }
    }
}

/// Failure reason for a concretisation stage.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConcretisationFailure {
    DeclarationViolations(Vec<DeclarationViolation>),
    CanonicalPathContractViolations(Vec<CanonicalPathContractViolation>),
    SchemaVersionDomainViolation { value: String },
    DeterministicIdCollisions(Vec<DeterministicIdCollision>),
    MissingTraceEntries(Vec<TraceEntryViolation>),
    TheoryViolations(Vec<TheoryViolation>),
}

/// Canonical path contract violation detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalPathContractViolation {
    pub namespace: String,
    pub path: String,
    pub reason: String,
}

/// Deterministic-id collision detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeterministicIdCollision {
    pub kind: DeterministicIdKind,
    pub first_path: String,
    pub second_path: String,
}

/// Canonical trace-map contract violation detail.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TraceEntryViolation {
    pub namespace: String,
    pub declaration_name: String,
    pub reason: String,
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

/// Compact deterministic progress score for concretisation loops.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConcretisationProgressScore {
    /// Number of stages that completed successfully.
    pub passed_stages: usize,
    /// Number of stages that were evaluated.
    pub total_stages: usize,
    /// Integer completion ratio in percent.
    pub completion_ratio: u8,
    /// First failed stage key, when any stage failed.
    pub first_failed_stage: Option<&'static str>,
}

impl ConcretisationReport {
    /// Returns true when every stage passed.
    pub fn passed(&self) -> bool {
        self.halted_at.is_none()
    }

    /// Computes a compact score for orchestration progress tracking.
    pub fn progress_score(&self) -> ConcretisationProgressScore {
        let total_stages = self.stages.len();
        let passed_stages = self.stages.iter().take_while(|stage| stage.passed).count();
        let completion_ratio = if total_stages == 0 {
            0
        } else {
            ((passed_stages * 100) / total_stages) as u8
        };
        let first_failed_stage = self
            .stages
            .iter()
            .find(|stage| !stage.passed)
            .map(|stage| stage.stage.stage_key());

        ConcretisationProgressScore {
            passed_stages,
            total_stages,
            completion_ratio,
            first_failed_stage,
        }
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
    pub trace: CanonicalTraceMap,
    pub theory: CoreTheoryLibrary,
}

/// Deterministic trace entry from declaration name to canonical object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalTraceEntry {
    pub canonical_path: String,
    pub deterministic_id: [u8; 16],
}

/// Deterministic declaration-to-canonical trace map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CanonicalTraceMap {
    pub model: CanonicalTraceEntry,
    pub zones: Vec<(DeclarationName, CanonicalTraceEntry)>,
    pub boundaries: Vec<(DeclarationName, CanonicalTraceEntry)>,
    pub routes: Vec<(DeclarationName, CanonicalTraceEntry)>,
    pub scopes: Vec<(DeclarationName, CanonicalTraceEntry)>,
    pub policies: Vec<(DeclarationName, CanonicalTraceEntry)>,
    pub requirements: Vec<(DeclarationName, CanonicalTraceEntry)>,
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
    let trace = build_canonical_trace_map(&paths, schema_version);

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
        trace,
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
    let path_contract_violations = validate_canonical_path_contracts(&paths);
    let paths_passed = path_contract_violations.is_empty();
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::DeriveCanonicalPaths,
        passed: paths_passed,
    });
    if !paths_passed {
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::DeriveCanonicalPaths),
            failure: Some(ConcretisationFailure::CanonicalPathContractViolations(
                path_contract_violations,
            )),
            canonical_model: None,
        };
    }

    // Smoke-check deterministic id derivation with model path.
    let schema_version = &normalized.declaration_version;
    let schema_value = schema_version.as_str();
    if !is_schema_version_domain_valid(schema_value) {
        stages.push(ConcretisationStageResult {
            stage: ConcretisationStage::DeriveDeterministicIds,
            passed: false,
        });
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::DeriveDeterministicIds),
            failure: Some(ConcretisationFailure::SchemaVersionDomainViolation {
                value: schema_value.to_owned(),
            }),
            canonical_model: None,
        };
    }
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
    let trace_violations = validate_trace_map_contract(&canonical_model);
    let trace_passed = trace_violations.is_empty();
    stages.push(ConcretisationStageResult {
        stage: ConcretisationStage::BuildCanonicalTheoryGraph,
        passed: trace_passed,
    });
    if !trace_passed {
        return ConcretisationReport {
            stages,
            halted_at: Some(ConcretisationStage::BuildCanonicalTheoryGraph),
            failure: Some(ConcretisationFailure::MissingTraceEntries(trace_violations)),
            canonical_model: Some(canonical_model),
        };
    }

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

fn build_canonical_trace_map(paths: &CanonicalPaths, schema_version: &SemVer) -> CanonicalTraceMap {
    let mut zones: Vec<_> = paths
        .zones
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Referent,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    zones.sort_by(|left, right| left.0.cmp(&right.0));

    let mut boundaries: Vec<_> = paths
        .boundaries
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Boundary,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    boundaries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut routes: Vec<_> = paths
        .routes
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Edge,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    routes.sort_by(|left, right| left.0.cmp(&right.0));

    let mut scopes: Vec<_> = paths
        .scopes
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Scope,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    scopes.sort_by(|left, right| left.0.cmp(&right.0));

    let mut policies: Vec<_> = paths
        .policies
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Policy,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    policies.sort_by(|left, right| left.0.cmp(&right.0));

    let mut requirements: Vec<_> = paths
        .requirements
        .iter()
        .map(|(name, path)| {
            (
                name.clone(),
                CanonicalTraceEntry {
                    canonical_path: path.clone(),
                    deterministic_id: derive_deterministic_id(
                        DeterministicIdKind::Requirement,
                        schema_version,
                        path,
                    ),
                },
            )
        })
        .collect();
    requirements.sort_by(|left, right| left.0.cmp(&right.0));

    CanonicalTraceMap {
        model: CanonicalTraceEntry {
            canonical_path: paths.model.clone(),
            deterministic_id: derive_deterministic_id(
                DeterministicIdKind::Model,
                schema_version,
                &paths.model,
            ),
        },
        zones,
        boundaries,
        routes,
        scopes,
        policies,
        requirements,
    }
}

pub fn validate_trace_map_contract(canonical_model: &CanonicalModel) -> Vec<TraceEntryViolation> {
    let mut violations = Vec::new();
    let schema_version = &canonical_model.normalized.declaration_version;
    let paths = &canonical_model.paths;
    let trace = &canonical_model.trace;

    if trace.model.canonical_path != paths.model {
        violations.push(TraceEntryViolation {
            namespace: "model".to_owned(),
            declaration_name: "model".to_owned(),
            reason: "canonical path mismatch".to_owned(),
        });
    }
    let expected_model_id =
        derive_deterministic_id(DeterministicIdKind::Model, schema_version, &paths.model);
    if trace.model.deterministic_id != expected_model_id {
        violations.push(TraceEntryViolation {
            namespace: "model".to_owned(),
            declaration_name: "model".to_owned(),
            reason: "deterministic id mismatch".to_owned(),
        });
    }

    validate_trace_entries(
        &mut violations,
        "zone",
        DeterministicIdKind::Referent,
        &paths.zones,
        &trace.zones,
        schema_version,
    );
    validate_trace_entries(
        &mut violations,
        "boundary",
        DeterministicIdKind::Boundary,
        &paths.boundaries,
        &trace.boundaries,
        schema_version,
    );
    validate_trace_entries(
        &mut violations,
        "route",
        DeterministicIdKind::Edge,
        &paths.routes,
        &trace.routes,
        schema_version,
    );
    validate_trace_entries(
        &mut violations,
        "scope",
        DeterministicIdKind::Scope,
        &paths.scopes,
        &trace.scopes,
        schema_version,
    );
    validate_trace_entries(
        &mut violations,
        "policy",
        DeterministicIdKind::Policy,
        &paths.policies,
        &trace.policies,
        schema_version,
    );
    validate_trace_entries(
        &mut violations,
        "requirement",
        DeterministicIdKind::Requirement,
        &paths.requirements,
        &trace.requirements,
        schema_version,
    );

    violations
}

fn validate_trace_entries(
    violations: &mut Vec<TraceEntryViolation>,
    namespace: &str,
    kind: DeterministicIdKind,
    expected_paths: &[(DeclarationName, String)],
    actual_entries: &[(DeclarationName, CanonicalTraceEntry)],
    schema_version: &SemVer,
) {
    let expected_by_name: BTreeMap<DeclarationName, String> = expected_paths
        .iter()
        .map(|(name, path)| (name.clone(), path.clone()))
        .collect();
    let actual_by_name: BTreeMap<DeclarationName, CanonicalTraceEntry> = actual_entries
        .iter()
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect();

    for (name, expected_path) in &expected_by_name {
        let Some(actual_entry) = actual_by_name.get(name) else {
            violations.push(TraceEntryViolation {
                namespace: namespace.to_owned(),
                declaration_name: name.as_str().to_owned(),
                reason: "missing trace entry".to_owned(),
            });
            continue;
        };

        if actual_entry.canonical_path != *expected_path {
            violations.push(TraceEntryViolation {
                namespace: namespace.to_owned(),
                declaration_name: name.as_str().to_owned(),
                reason: "canonical path mismatch".to_owned(),
            });
        }

        let expected_id = derive_deterministic_id(kind, schema_version, expected_path);
        if actual_entry.deterministic_id != expected_id {
            violations.push(TraceEntryViolation {
                namespace: namespace.to_owned(),
                declaration_name: name.as_str().to_owned(),
                reason: "deterministic id mismatch".to_owned(),
            });
        }
    }
}

fn validate_canonical_path_contracts(paths: &CanonicalPaths) -> Vec<CanonicalPathContractViolation> {
    let mut violations = Vec::new();
    let mut seen_by_namespace: BTreeMap<String, String> = BTreeMap::new();

    let mut record_namespace = |namespace: &str, path: &str| {
        let key = format!("{namespace}:{path}");
        if let Some(first) = seen_by_namespace.get(&key) {
            violations.push(CanonicalPathContractViolation {
                namespace: namespace.to_owned(),
                path: path.to_owned(),
                reason: format!("duplicate canonical path (first seen as {first})"),
            });
        } else {
            seen_by_namespace.insert(key, path.to_owned());
        }
    };

    record_namespace("model", &paths.model);
    record_namespace("actor", &paths.actor_system);
    for (_, path) in &paths.zones {
        record_namespace("referent", path);
    }
    for (_, path) in &paths.boundaries {
        record_namespace("boundary", path);
    }
    for (_, path) in &paths.scopes {
        record_namespace("scope", path);
    }
    for (_, path) in &paths.routes {
        record_namespace("edge", path);
    }
    for (_, path) in &paths.policies {
        record_namespace("policy", path);
    }
    for (_, path) in &paths.requirements {
        record_namespace("requirement", path);
    }
    for (_, path) in &paths.policy_scopes {
        record_namespace("scope", path);
    }

    validate_family_path(
        &mut violations,
        "model",
        &paths.model,
        "model/",
    );
    validate_family_path(
        &mut violations,
        "actor",
        &paths.actor_system,
        "actor/",
    );
    for (_, path) in &paths.scopes {
        validate_family_path(&mut violations, "scope", path, "scope/");
    }
    for (_, path) in &paths.policy_scopes {
        validate_family_path(&mut violations, "scope", path, "scope/");
    }
    for (_, path) in &paths.policies {
        validate_family_path(&mut violations, "policy", path, "policy/");
    }
    for (_, path) in &paths.requirements {
        validate_family_path(&mut violations, "requirement", path, "requirement/");
    }

    violations
}

fn validate_family_path(
    violations: &mut Vec<CanonicalPathContractViolation>,
    namespace: &str,
    path: &str,
    required_prefix: &str,
) {
    if !has_prefix_and_non_empty_name_segment(path, required_prefix) {
        violations.push(CanonicalPathContractViolation {
            namespace: namespace.to_owned(),
            path: path.to_owned(),
            reason: format!(
                "expected prefix `{required_prefix}` with non-empty name segment"
            ),
        });
    }
}

fn has_prefix_and_non_empty_name_segment(path: &str, required_prefix: &str) -> bool {
    let Some(remainder) = path.strip_prefix(required_prefix) else {
        return false;
    };
    if remainder.is_empty() {
        return false;
    }
    remainder
        .split('/')
        .next_back()
        .map(|segment| !segment.is_empty())
        .unwrap_or(false)
}

fn is_schema_version_domain_valid(version: &str) -> bool {
    if version.trim().is_empty() {
        return false;
    }

    let mut parts = version.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [major, minor, patch]
        .iter()
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
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
