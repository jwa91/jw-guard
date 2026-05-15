use alloc::vec::Vec;

use crate::structs::{
    ActorDeclaration, BoundaryDeclaration, CanonicalPaths, Claim, EdgeDeclaration, EvaluationDeclaration,
    ModelDeclaration, PolicyDeclaration, ReferentDeclaration, RequirementDeclaration, SourceDeclaration,
    TypedScopeDeclaration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeclaredModel {
    pub model: ModelDeclaration,
    pub actors: Vec<ActorDeclaration>,
    pub referents: Vec<ReferentDeclaration>,
    pub boundaries: Vec<BoundaryDeclaration>,
    pub edges: Vec<EdgeDeclaration>,
    pub scopes: Vec<TypedScopeDeclaration>,
    pub requirements: Vec<RequirementDeclaration>,
    pub policies: Vec<PolicyDeclaration>,
    pub canonical_paths: CanonicalPaths,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvidenceBasis {
    pub sources: Vec<SourceDeclaration>,
    pub claims: Vec<Claim>,
    pub evidence_items: Vec<crate::structs::EvidenceItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvaluatedModel {
    pub declared: DeclaredModel,
    pub evidence_basis: EvidenceBasis,
    pub evaluations: Vec<EvaluationDeclaration>,
}

