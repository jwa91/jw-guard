use alloc::vec::Vec;

use crate::{
    id::{
        ActorId, BoundaryId, EdgeId, EvaluationId, EvidenceSourceId, GateId, IdentityId, ModelId,
        ObservationId, PolicyId, ReferentId, RequirementId, RouteId, ScopeId, SurfaceId, ZoneId,
    },
    scalars::{GateSequence, NonEmptyVec, Port, Rate, UtcTimestamp},
    structs::{Boundary, BoundaryEnd, RouteEndpoints},
    theory::{
        ActorDeclaration, ActorRole, BoundaryDeclaration, EdgeDeclaration, EdgeSort,
        EvaluationContextDeclaration, EvaluationDeclaration, EvaluationResult,
        EvidenceSourceDeclaration, MembershipPredicateDeclaration, ModelDeclaration,
        ObservationDeclaration, PolicyDeclaration, PresenceOperator, ReferentDeclaration,
        ReferentSort, RequirementDeclaration, RequirementOperator, RequirementSort, SideDeclaration,
        SideLabel, SurfaceDeclaration, TypedScopeDeclaration, TypedValue,
    },
    theory_validation::{validate_core_theory_library, CoreTheoryLibrary},
};

/// Ordered concept layers derived from the terminology baseline.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ConceptLayer {
    /// Primitive scalar and branded-id atoms.
    PrimitiveDatatypes,
    /// Identity atoms (`ModelId`, `ActorId`, `ReferentId`).
    IdentityAtoms,
    /// Sort atoms (`ReferentSort`, `EdgeSort`, `RequirementSort`).
    SortAtoms,
    /// Graph atoms (`Referent`, `Boundary`, `Side`, `Surface`, `Edge`).
    GraphAtoms,
    /// Policy atoms (`Policy`, `TypedScope`, `Requirement`).
    PolicyAtoms,
    /// Evidence atoms (`EvidenceItem`, `EvidenceBasis`, `Evaluation`).
    EvidenceAtoms,
}

impl ConceptLayer {
    /// Stable stage key for progress reporting.
    pub const fn stage_key(self) -> &'static str {
        match self {
            Self::PrimitiveDatatypes => "primitive_datatypes",
            Self::IdentityAtoms => "identity_atoms",
            Self::SortAtoms => "sort_atoms",
            Self::GraphAtoms => "graph_atoms",
            Self::PolicyAtoms => "policy_atoms",
            Self::EvidenceAtoms => "evidence_atoms",
        }
    }
}

/// Severity for concept-layer findings.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AlignmentSeverity {
    /// Fundamental mismatch against the concept layer.
    Error,
    /// Non-fundamental mismatch that should still be resolved.
    Warning,
}

/// Single concept alignment finding.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AlignmentFinding {
    /// Error or warning.
    pub severity: AlignmentSeverity,
    /// Concept atom or declaration name.
    pub concept: &'static str,
    /// Deterministic explanation of the mismatch.
    pub detail: &'static str,
}

impl AlignmentFinding {
    fn error(concept: &'static str, detail: &'static str) -> Self {
        Self {
            severity: AlignmentSeverity::Error,
            concept,
            detail,
        }
    }
}

/// Evaluation outcome for one concept layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LayerFeedback {
    /// Layer that was evaluated.
    pub layer: ConceptLayer,
    /// Findings reported for this layer.
    pub findings: Vec<AlignmentFinding>,
}

impl LayerFeedback {
    fn new(layer: ConceptLayer, findings: Vec<AlignmentFinding>) -> Self {
        Self { layer, findings }
    }

    /// Returns true when this layer has no hard errors.
    pub fn passed(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|finding| finding.severity == AlignmentSeverity::Error)
    }
}

/// Strict gated feedback-loop report.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConceptFeedbackLoopReport {
    /// Evaluated layers, in order.
    pub layers: Vec<LayerFeedback>,
    /// First failing layer when the loop halts.
    pub halted_at: Option<ConceptLayer>,
}

/// Compact deterministic progress score for concept feedback loops.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConceptFeedbackProgressScore {
    /// Number of stages that completed successfully.
    pub passed_stages: usize,
    /// Number of stages that were evaluated.
    pub total_stages: usize,
    /// Integer completion ratio in percent.
    pub completion_ratio: u8,
    /// First failed stage key, when any stage failed.
    pub first_failed_stage: Option<&'static str>,
}

impl ConceptFeedbackLoopReport {
    /// Returns true when all evaluated layers passed and the loop reached the top layer.
    pub fn passed_all(&self) -> bool {
        self.halted_at.is_none()
    }

    /// Computes a compact score for orchestration progress tracking.
    pub fn progress_score(&self) -> ConceptFeedbackProgressScore {
        let total_stages = self.layers.len();
        let passed_stages = self.layers.iter().take_while(|layer| layer.passed()).count();
        let completion_ratio = if total_stages == 0 {
            0
        } else {
            ((passed_stages * 100) / total_stages) as u8
        };
        let first_failed_stage = self
            .layers
            .iter()
            .find(|layer| !layer.passed())
            .map(|layer| layer.layer.stage_key());

        ConceptFeedbackProgressScore {
            passed_stages,
            total_stages,
            completion_ratio,
            first_failed_stage,
        }
    }
}

/// Runs a severe gated concept feedback loop over core atoms.
///
/// The loop evaluates from primitive datatypes upward and only advances when the
/// current layer is error-free.
pub fn run_core_concept_feedback_loop() -> ConceptFeedbackLoopReport {
    let mut layers = Vec::new();
    let mut halted_at = None;
    let checks = [
        evaluate_primitive_datatypes as fn() -> LayerFeedback,
        evaluate_identity_atoms,
        evaluate_sort_atoms,
        evaluate_graph_atoms,
        evaluate_policy_atoms,
        evaluate_evidence_atoms,
    ];
    for check in checks {
        let feedback = check();
        let layer = feedback.layer;
        let passed = feedback.passed();
        layers.push(feedback);
        if !passed {
            halted_at = Some(layer);
            break;
        }
    }
    ConceptFeedbackLoopReport { layers, halted_at }
}

fn evaluate_primitive_datatypes() -> LayerFeedback {
    let mut findings = Vec::new();

    if Port::new(0).is_ok() {
        findings.push(AlignmentFinding::error(
            "Port",
            "port 0 must be rejected to keep boundary exposure atom non-empty",
        ));
    }
    if Rate::new(0).is_ok() {
        findings.push(AlignmentFinding::error(
            "Rate",
            "rate must be strictly positive for deterministic temporal constraints",
        ));
    }
    if GateSequence::new(0).is_ok() {
        findings.push(AlignmentFinding::error(
            "GateSequence",
            "gate sequence must be one-based to keep policy order meaningful",
        ));
    }
    if NonEmptyVec::<u8>::new(Vec::new(), "primitive_probe").is_ok() {
        findings.push(AlignmentFinding::error(
            "NonEmptyVec",
            "non-empty atom accepted empty payload",
        ));
    }
    if UtcTimestamp::new("not-a-timestamp").is_ok() {
        findings.push(AlignmentFinding::error(
            "UtcTimestamp",
            "timestamp atom accepted invalid UTC format",
        ));
    }
    if ZoneId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || BoundaryId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || SurfaceId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || RouteId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || GateId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || IdentityId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || ScopeId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || PolicyId::from_bytes([0u8; 16]).as_bytes().len() != 16
        || ActorId::from_bytes([0u8; 16]).as_bytes().len() != 16
    {
        findings.push(AlignmentFinding::error(
            "BrandedId",
            "core branded ids must be fixed-width 128-bit atoms",
        ));
    }

    LayerFeedback::new(ConceptLayer::PrimitiveDatatypes, findings)
}

fn evaluate_identity_atoms() -> LayerFeedback {
    let mut findings = Vec::new();
    if ModelId::from_bytes([0u8; 16]).as_bytes().len() != 16 {
        findings.push(AlignmentFinding::error(
            "ModelId",
            "model identity atom is not fixed-width 128-bit",
        ));
    }
    if ReferentId::from_bytes([0u8; 16]).as_bytes().len() != 16 {
        findings.push(AlignmentFinding::error(
            "ReferentId",
            "referent identity atom is not fixed-width 128-bit",
        ));
    }
    let actor = ActorDeclaration {
        id: ActorId::from_bytes([1u8; 16]),
        role: ActorRole::System,
    };
    let model = ModelDeclaration {
        id: ModelId::from_bytes([2u8; 16]),
        version: crate::scalars::SemVer::new("1.0.0").expect("valid semver"),
        declared_at: crate::scalars::UtcTimestamp::new("2026-01-01T00:00:00Z")
            .expect("valid timestamp"),
        declared_by: actor.id,
    };
    let referent = ReferentDeclaration {
        id: ReferentId::from_bytes([3u8; 16]),
        sort: ReferentSort::Actor,
    };
    if model.declared_by != actor.id || !matches!(referent.sort, ReferentSort::Actor) {
        findings.push(AlignmentFinding::error(
            "IdentityAtoms",
            "identity atoms failed deterministic declaration wiring",
        ));
    }

    LayerFeedback::new(ConceptLayer::IdentityAtoms, findings)
}

fn evaluate_sort_atoms() -> LayerFeedback {
    let mut findings = Vec::new();
    let sort = ReferentSort::ReleaseArtifact;
    let edge = EdgeSort::CrossesBoundary;
    let req_sort = RequirementSort::Presence;
    let req = RequirementDeclaration::new(
        RequirementId::from_bytes([4u8; 16]),
        req_sort.clone(),
        RequirementOperator::Presence(PresenceOperator::Required),
        TypedValue::Bool(true),
    );
    if !matches!(sort, ReferentSort::ReleaseArtifact)
        || !matches!(edge, EdgeSort::CrossesBoundary)
        || req.is_err()
    {
        findings.push(AlignmentFinding::error(
            "SortAtoms",
            "sort atoms failed to produce coherent typed requirement form",
        ));
    }
    LayerFeedback::new(ConceptLayer::SortAtoms, findings)
}

fn evaluate_graph_atoms() -> LayerFeedback {
    let mut findings = Vec::new();
    if Boundary::new(
        BoundaryId::from_bytes([1u8; 16]),
        BoundaryEnd::Outside,
        BoundaryEnd::Outside,
    )
    .is_ok()
    {
        findings.push(AlignmentFinding::error(
            "Boundary",
            "boundary accepted outside-to-outside and broke separation axiom",
        ));
    }
    if RouteEndpoints::new(BoundaryEnd::Outside, BoundaryEnd::Outside).is_ok() {
        findings.push(AlignmentFinding::error(
            "Side",
            "route endpoints accepted outside-to-outside and broke side anchoring",
        ));
    }
    let left = ReferentId::from_bytes([10u8; 16]);
    let right = ReferentId::from_bytes([11u8; 16]);
    let side_a = SideDeclaration {
        label: SideLabel::A,
        anchor: left,
    };
    let side_b = SideDeclaration {
        label: SideLabel::B,
        anchor: right,
    };
    let boundary_id = BoundaryId::from_bytes([12u8; 16]);
    let surface_a = SurfaceDeclaration {
        id: SurfaceId::from_bytes([13u8; 16]),
        boundary_id,
        facing: SideLabel::A,
    };
    let surface_b = SurfaceDeclaration {
        id: SurfaceId::from_bytes([14u8; 16]),
        boundary_id,
        facing: SideLabel::B,
    };
    if BoundaryDeclaration::new(boundary_id, side_a, side_b, surface_a, surface_b).is_err() {
        findings.push(AlignmentFinding::error(
            "BoundaryDeclaration",
            "graph atoms failed to construct two-sided boundary declaration",
        ));
    }
    if EdgeDeclaration::new(
        EdgeId::from_bytes([15u8; 16]),
        EdgeSort::CrossesBoundary,
        left,
        right,
    )
    .is_err()
    {
        findings.push(AlignmentFinding::error(
            "EdgeDeclaration",
            "graph atoms failed to construct typed edge declaration",
        ));
    }
    LayerFeedback::new(ConceptLayer::GraphAtoms, findings)
}

fn evaluate_policy_atoms() -> LayerFeedback {
    let mut findings = Vec::new();
    let context = EvaluationContextDeclaration {
        model_version: crate::scalars::SemVer::new("1.0.0").expect("valid semver"),
        namespace: None,
        boundary: None,
        actor_authority: None,
        snapshot_at: None,
        evidence_source: None,
    };
    let scope = TypedScopeDeclaration {
        id: ScopeId::from_bytes([20u8; 16]),
        referent_sort: ReferentSort::ReleaseArtifact,
        context,
        predicate: MembershipPredicateDeclaration::All,
    };
    let requirement = RequirementDeclaration::new(
        RequirementId::from_bytes([21u8; 16]),
        RequirementSort::Count,
        RequirementOperator::Count(crate::theory::CountOperator::Min),
        TypedValue::U64(1),
    );
    let policy = PolicyDeclaration {
        id: PolicyId::from_bytes([22u8; 16]),
        declared_by: ActorId::from_bytes([23u8; 16]),
        scope: scope.id,
        requirement: RequirementId::from_bytes([21u8; 16]),
    };
    if requirement.is_err() || policy.scope != scope.id {
        findings.push(AlignmentFinding::error(
            "PolicyAtoms",
            "policy atom form failed to bind actor + typed-scope + requirement",
        ));
    }
    LayerFeedback::new(ConceptLayer::PolicyAtoms, findings)
}

fn evaluate_evidence_atoms() -> LayerFeedback {
    let mut findings = Vec::new();
    let source_id = EvidenceSourceId::from_bytes([30u8; 16]);
    let source = EvidenceSourceDeclaration {
        id: source_id,
        source_type: crate::scalars::NonEmptyString::new("scanner").expect("non-empty"),
        mapper: crate::scalars::NonEmptyString::new("mapper-v1").expect("non-empty"),
        trust_assumption: crate::scalars::NonEmptyString::new("signed feed").expect("non-empty"),
    };
    let observation = ObservationDeclaration {
        id: ObservationId::from_bytes([31u8; 16]),
        source: source.id,
        observed_referent: Some(ReferentId::from_bytes([32u8; 16])),
        observed_sort: ReferentSort::ReleaseArtifact,
        at: crate::scalars::UtcTimestamp::new("2026-01-01T00:00:00Z")
            .expect("valid timestamp"),
        claim: TypedValue::Bool(true),
    };
    let evidence_basis = NonEmptyVec::from_item(observation.id);
    let evaluation = EvaluationDeclaration {
        id: EvaluationId::from_bytes([33u8; 16]),
        policy: PolicyId::from_bytes([22u8; 16]),
        evidence_basis,
        result: EvaluationResult::Unknown,
    };
    if evaluation.evidence_basis.is_empty() || source.id != observation.source {
        findings.push(AlignmentFinding::error(
            "EvidenceAtoms",
            "evidence atoms failed to produce deterministic evaluation declaration",
        ));
    }
    let minimal_library = CoreTheoryLibrary {
        model: ModelDeclaration {
            id: ModelId::from_bytes([35u8; 16]),
            version: crate::scalars::SemVer::new("1.0.0").expect("valid semver"),
            declared_at: crate::scalars::UtcTimestamp::new("2026-01-01T00:00:00Z")
                .expect("valid timestamp"),
            declared_by: ActorId::from_bytes([36u8; 16]),
        },
        actors: alloc::vec![ActorDeclaration {
            id: ActorId::from_bytes([36u8; 16]),
            role: ActorRole::System,
        }],
        referents: alloc::vec![
            ReferentDeclaration {
                id: ReferentId::from_bytes([32u8; 16]),
                sort: ReferentSort::ReleaseArtifact,
            },
            ReferentDeclaration {
                id: ReferentId::from_bytes([37u8; 16]),
                sort: ReferentSort::Boundary,
            },
        ],
        boundaries: alloc::vec![BoundaryDeclaration::new(
            BoundaryId::from_bytes([38u8; 16]),
            SideDeclaration {
                label: SideLabel::A,
                anchor: ReferentId::from_bytes([37u8; 16]),
            },
            SideDeclaration {
                label: SideLabel::B,
                anchor: ReferentId::from_bytes([32u8; 16]),
            },
            SurfaceDeclaration {
                id: SurfaceId::from_bytes([39u8; 16]),
                boundary_id: BoundaryId::from_bytes([38u8; 16]),
                facing: SideLabel::A,
            },
            SurfaceDeclaration {
                id: SurfaceId::from_bytes([40u8; 16]),
                boundary_id: BoundaryId::from_bytes([38u8; 16]),
                facing: SideLabel::B,
            },
        )
        .expect("coherent boundary")],
        edges: alloc::vec![EdgeDeclaration::new(
            EdgeId::from_bytes([41u8; 16]),
            EdgeSort::CrossesBoundary,
            ReferentId::from_bytes([37u8; 16]),
            ReferentId::from_bytes([32u8; 16]),
        )
        .expect("coherent edge")],
        scopes: alloc::vec![TypedScopeDeclaration {
            id: ScopeId::from_bytes([20u8; 16]),
            referent_sort: ReferentSort::ReleaseArtifact,
            context: EvaluationContextDeclaration {
                model_version: crate::scalars::SemVer::new("1.0.0").expect("valid semver"),
                namespace: None,
                boundary: None,
                actor_authority: None,
                snapshot_at: None,
                evidence_source: None,
            },
            predicate: MembershipPredicateDeclaration::ReferentIds {
                ids: NonEmptyVec::from_item(ReferentId::from_bytes([32u8; 16])),
            },
        }],
        requirements: alloc::vec![RequirementDeclaration::new(
            RequirementId::from_bytes([21u8; 16]),
            RequirementSort::Count,
            RequirementOperator::Count(crate::theory::CountOperator::Min),
            TypedValue::U64(1),
        )
        .expect("coherent requirement")],
        policies: alloc::vec![PolicyDeclaration {
            id: PolicyId::from_bytes([22u8; 16]),
            declared_by: ActorId::from_bytes([36u8; 16]),
            scope: ScopeId::from_bytes([20u8; 16]),
            requirement: RequirementId::from_bytes([21u8; 16]),
        }],
        evidence_sources: alloc::vec![source],
        observations: alloc::vec![observation],
        evaluations: alloc::vec![evaluation],
    };
    if !validate_core_theory_library(&minimal_library).is_empty() {
        findings.push(AlignmentFinding::error(
            "TheoryValidation",
            "minimal theory library failed deterministic reference validation",
        ));
    }
    LayerFeedback::new(ConceptLayer::EvidenceAtoms, findings)
}
