use alloc::{collections::BTreeSet, vec::Vec};

use crate::{
    id::{
        ActorId, BoundaryId, EdgeId, EvaluationId, EvidenceSourceId, ObservationId, PolicyId,
        ReferentId, RequirementId, ScopeId,
    },
    theory::{
        ActorDeclaration, BoundaryDeclaration, EdgeDeclaration, EvaluationDeclaration,
        EvidenceSourceDeclaration, MembershipPredicateDeclaration, ModelDeclaration,
        ObservationDeclaration, PolicyDeclaration, ReferentDeclaration, RequirementDeclaration,
        RequirementOperator, RequirementSort, SideLabel, TypedScopeDeclaration, TypedValue,
    },
};

/// Subject tied to a theory-layer violation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TheorySubject {
    Model,
    Actor(ActorId),
    Referent(ReferentId),
    Boundary(BoundaryId),
    Edge(EdgeId),
    Scope(ScopeId),
    Requirement(RequirementId),
    Policy(PolicyId),
    EvidenceSource(EvidenceSourceId),
    Observation(ObservationId),
    Evaluation(EvaluationId),
}

/// Machine-readable theory validity code.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TheoryViolationCode {
    EmptyRequiredSet,
    DuplicateId,
    MissingReference,
    ScopeSortMismatch,
    ContextInvariant,
}

/// Theory-level validation violation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TheoryViolation {
    pub code: TheoryViolationCode,
    pub subject: TheorySubject,
}

impl TheoryViolation {
    fn new(code: TheoryViolationCode, subject: TheorySubject) -> Self {
        Self { code, subject }
    }
}

/// Unopinionated type-theory library aggregate for system security modeling.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CoreTheoryLibrary {
    pub model: ModelDeclaration,
    pub actors: Vec<ActorDeclaration>,
    pub referents: Vec<ReferentDeclaration>,
    pub boundaries: Vec<BoundaryDeclaration>,
    pub edges: Vec<EdgeDeclaration>,
    pub scopes: Vec<TypedScopeDeclaration>,
    pub requirements: Vec<RequirementDeclaration>,
    pub policies: Vec<PolicyDeclaration>,
    pub evidence_sources: Vec<EvidenceSourceDeclaration>,
    pub observations: Vec<ObservationDeclaration>,
    pub evaluations: Vec<EvaluationDeclaration>,
}

/// Validates minimum declaration coherence for the abstract theory library.
pub fn validate_core_theory_library(library: &CoreTheoryLibrary) -> Vec<TheoryViolation> {
    let mut violations = Vec::new();

    if library.actors.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }
    if library.boundaries.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }
    if library.edges.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }
    if library.scopes.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }
    if library.requirements.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }
    if library.policies.is_empty() {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::EmptyRequiredSet,
            TheorySubject::Model,
        ));
    }

    violations.extend(validate_unique_actors(&library.actors));
    violations.extend(validate_unique_referents(&library.referents));
    violations.extend(validate_unique_boundaries(&library.boundaries));
    violations.extend(validate_unique_edges(&library.edges));
    violations.extend(validate_unique_scopes(&library.scopes));
    violations.extend(validate_unique_requirements(&library.requirements));
    violations.extend(validate_unique_policies(&library.policies));
    violations.extend(validate_unique_evidence_sources(&library.evidence_sources));
    violations.extend(validate_unique_observations(&library.observations));
    violations.extend(validate_unique_evaluations(&library.evaluations));

    if !library
        .actors
        .iter()
        .any(|actor| actor.id == library.model.declared_by)
    {
        violations.push(TheoryViolation::new(
            TheoryViolationCode::MissingReference,
            TheorySubject::Model,
        ));
    }

    for edge in &library.edges {
        if !library.referents.iter().any(|referent| referent.id == edge.from)
            || !library.referents.iter().any(|referent| referent.id == edge.to)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::MissingReference,
                TheorySubject::Edge(edge.id),
            ));
        }
    }

    for boundary in &library.boundaries {
        if boundary.side_a.label != SideLabel::A || boundary.side_b.label != SideLabel::B {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Boundary(boundary.id),
            ));
        }
        if boundary.surface_a.facing != SideLabel::A || boundary.surface_b.facing != SideLabel::B {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Boundary(boundary.id),
            ));
        }
        if boundary.surface_a.boundary_id != boundary.id || boundary.surface_b.boundary_id != boundary.id
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Boundary(boundary.id),
            ));
        }
        if boundary.side_a.anchor == boundary.side_b.anchor {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Boundary(boundary.id),
            ));
        }
        if !library
            .referents
            .iter()
            .any(|referent| referent.id == boundary.side_a.anchor)
            || !library
                .referents
                .iter()
                .any(|referent| referent.id == boundary.side_b.anchor)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::MissingReference,
                TheorySubject::Boundary(boundary.id),
            ));
        }
    }

    for scope in &library.scopes {
        if scope.context.model_version != library.model.version {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Scope(scope.id),
            ));
        }
        if let MembershipPredicateDeclaration::ReferentIds { ids } = &scope.predicate {
            for referent_id in ids.as_slice() {
                let referent = library
                    .referents
                    .iter()
                    .find(|candidate| candidate.id == *referent_id);
                let Some(referent) = referent else {
                    violations.push(TheoryViolation::new(
                        TheoryViolationCode::MissingReference,
                        TheorySubject::Scope(scope.id),
                    ));
                    continue;
                };
                if referent.sort != scope.referent_sort {
                    violations.push(TheoryViolation::new(
                        TheoryViolationCode::ScopeSortMismatch,
                        TheorySubject::Scope(scope.id),
                    ));
                }
            }
        }
        if let MembershipPredicateDeclaration::EdgeTo(edge_to) = &scope.predicate {
            if scope.referent_sort != edge_to.source_sort {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::ContextInvariant,
                    TheorySubject::Scope(scope.id),
                ));
            }

            let to_referent_exists = library
                .referents
                .iter()
                .any(|candidate| candidate.id == edge_to.to);
            if !to_referent_exists {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::MissingReference,
                    TheorySubject::Scope(scope.id),
                ));
                continue;
            }

            let mut has_matching_edge = false;
            for edge in library
                .edges
                .iter()
                .filter(|edge| edge.sort == edge_to.edge_sort && edge.to == edge_to.to)
            {
                has_matching_edge = true;
                let from_referent = library
                    .referents
                    .iter()
                    .find(|candidate| candidate.id == edge.from);
                let Some(from_referent) = from_referent else {
                    violations.push(TheoryViolation::new(
                        TheoryViolationCode::MissingReference,
                        TheorySubject::Scope(scope.id),
                    ));
                    continue;
                };
                if from_referent.sort != edge_to.source_sort {
                    violations.push(TheoryViolation::new(
                        TheoryViolationCode::ScopeSortMismatch,
                        TheorySubject::Scope(scope.id),
                    ));
                }
            }

            if !has_matching_edge {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::MissingReference,
                    TheorySubject::Scope(scope.id),
                ));
            }
        }
    }

    for requirement in &library.requirements {
        if !operator_matches_value(&requirement.operator, &requirement.value)
            || !sort_matches_operator(&requirement.sort, &requirement.operator)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::ContextInvariant,
                TheorySubject::Requirement(requirement.id),
            ));
        }
    }

    for policy in &library.policies {
        if !library.actors.iter().any(|actor| actor.id == policy.declared_by)
            || !library.scopes.iter().any(|scope| scope.id == policy.scope)
            || !library
                .requirements
                .iter()
                .any(|requirement| requirement.id == policy.requirement)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::MissingReference,
                TheorySubject::Policy(policy.id),
            ));
        }
    }

    for observation in &library.observations {
        if !library
            .evidence_sources
            .iter()
            .any(|source| source.id == observation.source)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::MissingReference,
                TheorySubject::Observation(observation.id),
            ));
        }
        if let Some(referent_id) = observation.observed_referent {
            let referent = library
                .referents
                .iter()
                .find(|candidate| candidate.id == referent_id);
            let Some(referent) = referent else {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::MissingReference,
                    TheorySubject::Observation(observation.id),
                ));
                continue;
            };
            if referent.sort != observation.observed_sort {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::ScopeSortMismatch,
                    TheorySubject::Observation(observation.id),
                ));
            }
        }
    }

    for evaluation in &library.evaluations {
        if !library
            .policies
            .iter()
            .any(|policy| policy.id == evaluation.policy)
        {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::MissingReference,
                TheorySubject::Evaluation(evaluation.id),
            ));
        }
        for observation in evaluation.evidence_basis.references.as_slice() {
            if !library
                .observations
                .iter()
                .any(|candidate| candidate.id == *observation)
            {
                violations.push(TheoryViolation::new(
                    TheoryViolationCode::MissingReference,
                    TheorySubject::Evaluation(evaluation.id),
                ));
            }
        }
    }

    violations
}

fn validate_unique_actors(actors: &[ActorDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for actor in actors {
        if !seen.insert(actor.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Actor(actor.id),
            ));
        }
    }
    violations
}

fn validate_unique_referents(referents: &[ReferentDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for referent in referents {
        if !seen.insert(referent.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Referent(referent.id),
            ));
        }
    }
    violations
}

fn validate_unique_boundaries(boundaries: &[BoundaryDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for boundary in boundaries {
        if !seen.insert(boundary.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Boundary(boundary.id),
            ));
        }
    }
    violations
}

fn validate_unique_edges(edges: &[EdgeDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for edge in edges {
        if !seen.insert(edge.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Edge(edge.id),
            ));
        }
    }
    violations
}

fn validate_unique_scopes(scopes: &[TypedScopeDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for scope in scopes {
        if !seen.insert(scope.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Scope(scope.id),
            ));
        }
    }
    violations
}

fn validate_unique_requirements(requirements: &[RequirementDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for requirement in requirements {
        if !seen.insert(requirement.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Requirement(requirement.id),
            ));
        }
    }
    violations
}

fn validate_unique_policies(policies: &[PolicyDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for policy in policies {
        if !seen.insert(policy.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Policy(policy.id),
            ));
        }
    }
    violations
}

fn validate_unique_evidence_sources(
    evidence_sources: &[EvidenceSourceDeclaration],
) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for source in evidence_sources {
        if !seen.insert(source.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::EvidenceSource(source.id),
            ));
        }
    }
    violations
}

fn validate_unique_observations(observations: &[ObservationDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for observation in observations {
        if !seen.insert(observation.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Observation(observation.id),
            ));
        }
    }
    violations
}

fn validate_unique_evaluations(evaluations: &[EvaluationDeclaration]) -> Vec<TheoryViolation> {
    let mut seen = BTreeSet::new();
    let mut violations = Vec::new();
    for evaluation in evaluations {
        if !seen.insert(evaluation.id) {
            violations.push(TheoryViolation::new(
                TheoryViolationCode::DuplicateId,
                TheorySubject::Evaluation(evaluation.id),
            ));
        }
    }
    violations
}

fn operator_matches_value(operator: &RequirementOperator, value: &TypedValue) -> bool {
    match operator {
        RequirementOperator::Presence(_) => matches!(value, TypedValue::Bool(_)),
        RequirementOperator::Order(_) | RequirementOperator::Count(_) => {
            matches!(value, TypedValue::U64(_))
        }
        RequirementOperator::Set(_) => matches!(
            value,
            TypedValue::String(_) | TypedValue::ReferentSort(_) | TypedValue::EdgeSort(_)
        ),
        RequirementOperator::Temporal(_) => {
            matches!(value, TypedValue::Timestamp(_) | TypedValue::U64(_))
        }
        RequirementOperator::Relation(_) => matches!(
            value,
            TypedValue::U64(_)
                | TypedValue::Bool(_)
                | TypedValue::ReferentSort(_)
                | TypedValue::EdgeSort(_)
        ),
    }
}

fn sort_matches_operator(sort: &RequirementSort, operator: &RequirementOperator) -> bool {
    matches!(
        (sort, operator),
        (RequirementSort::Presence, RequirementOperator::Presence(_))
            | (RequirementSort::Order, RequirementOperator::Order(_))
            | (RequirementSort::SetMembership, RequirementOperator::Set(_))
            | (RequirementSort::Count, RequirementOperator::Count(_))
            | (RequirementSort::Temporal, RequirementOperator::Temporal(_))
            | (RequirementSort::Relation, RequirementOperator::Relation(_))
            | (RequirementSort::Custom { .. }, _)
    )
}
