use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::DeclareError;
use crate::spec::{DeclaredSpec, RequirementValueSpec, ScopePredicateSpec, VersionSpec};
use crate::validation::validate_spec;
use jw_guard_canon::{stable_sort_by_key, CanonicalPath, DeterministicId};
use jw_guard_core::{
    ActorDeclaration, ActorId, BoundaryDeclaration, BoundaryId, CanonicalName, CanonicalPaths, DeclaredModel,
    Direction, EdgeDeclaration, EdgeId, EdgeSortId, Endpoint, EndpointRole, EvaluationContext, MembershipPredicate,
    ModelDeclaration, ModelId, PolicyDeclaration, PolicyId, ReferentDeclaration, ReferentId, ReferentSortId,
    RequirementDeclaration, RequirementId, RequirementSortId, RequirementValue, ScopeId, SideDeclaration, SideId,
    SurfaceDeclaration, SurfaceFacing, SurfaceId, Timestamp, TypedScopeDeclaration,
};

pub fn concretise(spec: &DeclaredSpec) -> Result<DeclaredModel, DeclareError> {
    let validation_errors = validate_spec(spec);
    if !validation_errors.is_empty() {
        return Err(DeclareError::ValidationFailed(validation_errors));
    }

    let model_path = canonical_path("model", spec.model.name.as_str())?;
    let model_id = ModelId::from_bytes(derive_id(
        "model",
        spec.schema_version.as_str(),
        model_path.as_str(),
    )?);

    let mut actor_specs = spec.actors.clone();
    let mut referent_specs = spec.referents.clone();
    let mut boundary_specs = spec.boundaries.clone();
    let mut edge_specs = spec.edges.clone();
    let mut scope_specs = spec.scopes.clone();
    let mut requirement_specs = spec.requirements.clone();
    let mut policy_specs = spec.policies.clone();

    stable_sort_by_key(&mut actor_specs, |item| item.name.clone());
    stable_sort_by_key(&mut referent_specs, |item| item.name.clone());
    stable_sort_by_key(&mut boundary_specs, |item| item.name.clone());
    stable_sort_by_key(&mut edge_specs, |item| item.name.clone());
    stable_sort_by_key(&mut scope_specs, |item| item.name.clone());
    stable_sort_by_key(&mut requirement_specs, |item| item.name.clone());
    stable_sort_by_key(&mut policy_specs, |item| item.name.clone());

    let mut actor_paths = Vec::new();
    let mut actors = Vec::new();
    let mut actor_ids = BTreeMap::new();
    for actor in actor_specs {
        let path = canonical_path("actor", actor.name.as_str())?;
        let id = ActorId::from_bytes(derive_id("actor", spec.schema_version.as_str(), path.as_str())?);
        actor_paths.push(path.to_string());
        actor_ids.insert(actor.name, id);
        actors.push(ActorDeclaration {
            id,
            role: CanonicalName::new(actor.role.as_str().into())?,
        });
    }

    let mut referent_paths = Vec::new();
    let mut referents = Vec::new();
    let mut referent_ids = BTreeMap::new();
    for referent in referent_specs {
        let path = canonical_path("referent", referent.name.as_str())?;
        let id = ReferentId::from_bytes(derive_id(
            "referent",
            spec.schema_version.as_str(),
            path.as_str(),
        )?);
        referent_paths.push(path.to_string());
        referent_ids.insert(referent.name, id);
        referents.push(ReferentDeclaration {
            id,
            sort: ReferentSortId(referent.sort),
        });
    }

    let mut boundary_paths = Vec::new();
    let mut boundaries = Vec::new();
    for boundary in boundary_specs {
        let boundary_path = canonical_path("boundary", boundary.name.as_str())?;
        let boundary_id = BoundaryId::from_bytes(derive_id(
            "boundary",
            spec.schema_version.as_str(),
            boundary_path.as_str(),
        )?);

        let side_a_anchor = *referent_ids
            .get(&boundary.side_a_anchor)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "boundaries",
                field: "side_a_anchor",
                name: boundary.side_a_anchor.as_str().to_string(),
            })?;
        let side_b_anchor = *referent_ids
            .get(&boundary.side_b_anchor)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "boundaries",
                field: "side_b_anchor",
                name: boundary.side_b_anchor.as_str().to_string(),
            })?;

        let declaration = BoundaryDeclaration::new(
            boundary_id,
            SideDeclaration {
                id: SideId::from_bytes(derive_id(
                    "side",
                    spec.schema_version.as_str(),
                    boundary_path.join("side_a")?.as_str(),
                )?),
                boundary_id,
                anchor_referent: side_a_anchor,
            },
            SideDeclaration {
                id: SideId::from_bytes(derive_id(
                    "side",
                    spec.schema_version.as_str(),
                    boundary_path.join("side_b")?.as_str(),
                )?),
                boundary_id,
                anchor_referent: side_b_anchor,
            },
            SurfaceDeclaration {
                id: SurfaceId::from_bytes(derive_id(
                    "surface",
                    spec.schema_version.as_str(),
                    boundary_path.join("surface_a")?.as_str(),
                )?),
                boundary_id,
                facing: SurfaceFacing::A,
            },
            SurfaceDeclaration {
                id: SurfaceId::from_bytes(derive_id(
                    "surface",
                    spec.schema_version.as_str(),
                    boundary_path.join("surface_b")?.as_str(),
                )?),
                boundary_id,
                facing: SurfaceFacing::B,
            },
        )?;

        boundary_paths.push(boundary_path.to_string());
        boundaries.push(declaration);
    }

    let mut edge_paths = Vec::new();
    let mut edges = Vec::new();
    for edge in edge_specs {
        let path = canonical_path("edge", edge.name.as_str())?;
        let edge_id = EdgeId::from_bytes(derive_id("edge", spec.schema_version.as_str(), path.as_str())?);
        let first = *referent_ids
            .get(&edge.first)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "edges",
                field: "first",
                name: edge.first.as_str().to_string(),
            })?;
        let second = *referent_ids
            .get(&edge.second)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "edges",
                field: "second",
                name: edge.second.as_str().to_string(),
            })?;

        let (first_role, second_role) = endpoint_roles(edge.direction);
        let declaration = EdgeDeclaration::new(
            edge_id,
            EdgeSortId(edge.sort),
            edge.direction,
            Endpoint {
                role: first_role,
                referent_id: first,
            },
            Endpoint {
                role: second_role,
                referent_id: second,
            },
        )?;
        edge_paths.push(path.to_string());
        edges.push(declaration);
    }

    let mut scope_paths = Vec::new();
    let mut scopes = Vec::new();
    let mut scope_ids = BTreeMap::new();
    for scope in scope_specs {
        let path = canonical_path("scope", scope.name.as_str())?;
        let scope_id = ScopeId::from_bytes(derive_id("scope", spec.schema_version.as_str(), path.as_str())?);

        let context = EvaluationContext {
            model_version: to_semver(&spec.model.version),
            snapshot: Timestamp::from_unix_seconds(scope.snapshot_unix_seconds),
            namespace: CanonicalName::new(scope.namespace.as_str().into())?,
            mapper_version: to_semver(&scope.mapper_version),
        };
        let predicate = match scope.predicate {
            ScopePredicateSpec::All => MembershipPredicate::All,
            ScopePredicateSpec::HasTag(tag) => MembershipPredicate::HasTag(CanonicalName::new(tag.as_str().into())?),
            ScopePredicateSpec::NameEquals(name) => {
                MembershipPredicate::NameEquals(CanonicalName::new(name.as_str().into())?)
            }
        };

        scope_paths.push(path.to_string());
        scope_ids.insert(scope.name, scope_id);
        scopes.push(TypedScopeDeclaration::new(
            scope_id,
            ReferentSortId(scope.referent_sort),
            context,
            predicate,
        ));
    }

    let mut requirement_paths = Vec::new();
    let mut requirements = Vec::new();
    let mut requirement_ids = BTreeMap::new();
    for requirement in requirement_specs {
        let path = canonical_path("requirement", requirement.name.as_str())?;
        let requirement_id = RequirementId::from_bytes(derive_id(
            "requirement",
            spec.schema_version.as_str(),
            path.as_str(),
        )?);
        let declaration = RequirementDeclaration::new(
            requirement_id,
            RequirementSortId(requirement.sort),
            requirement.operator,
            requirement_value(&requirement.value)?,
        )?;

        requirement_paths.push(path.to_string());
        requirement_ids.insert(requirement.name, requirement_id);
        requirements.push(declaration);
    }

    let mut policy_paths = Vec::new();
    let mut policies = Vec::new();
    for policy in policy_specs {
        let path = canonical_path("policy", policy.name.as_str())?;
        let policy_id = PolicyId::from_bytes(derive_id("policy", spec.schema_version.as_str(), path.as_str())?);
        let declared_by = *actor_ids
            .get(&policy.declared_by)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "policies",
                field: "declared_by",
                name: policy.declared_by.as_str().to_string(),
            })?;
        let scope = *scope_ids
            .get(&policy.scope)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "policies",
                field: "scope",
                name: policy.scope.as_str().to_string(),
            })?;
        let requirement = *requirement_ids
            .get(&policy.requirement)
            .ok_or_else(|| DeclareError::MissingReference {
                section: "policies",
                field: "requirement",
                name: policy.requirement.as_str().to_string(),
            })?;

        policy_paths.push(path.to_string());
        policies.push(PolicyDeclaration::new(policy_id, declared_by, scope, requirement));
    }

    Ok(DeclaredModel {
        model: ModelDeclaration {
            id: model_id,
            version: to_semver(&spec.model.version),
            declared_at: Timestamp::from_unix_seconds(spec.model.declared_at_unix_seconds),
            declared_by: *actor_ids
                .get(&spec.model.declared_by)
                .ok_or_else(|| DeclareError::MissingReference {
                    section: "model",
                    field: "declared_by",
                    name: spec.model.declared_by.as_str().to_string(),
                })?,
        },
        actors,
        referents,
        boundaries,
        edges,
        scopes,
        requirements,
        policies,
        canonical_paths: CanonicalPaths {
            model: model_path.to_string(),
            actors: actor_paths,
            referents: referent_paths,
            boundaries: boundary_paths,
            edges: edge_paths,
            scopes: scope_paths,
            requirements: requirement_paths,
            policies: policy_paths,
        },
    })
}

fn endpoint_roles(direction: Direction) -> (EndpointRole, EndpointRole) {
    match direction {
        Direction::Directed => (EndpointRole::From, EndpointRole::To),
        Direction::Undirected => (EndpointRole::EndpointA, EndpointRole::EndpointB),
    }
}

fn canonical_path(kind: &str, name: &str) -> Result<CanonicalPath, DeclareError> {
    Ok(CanonicalPath::from_segments([kind, name])?)
}

fn derive_id(id_kind: &str, schema_version: &str, canonical_path: &str) -> Result<[u8; 16], DeclareError> {
    Ok(DeterministicId::derive(id_kind, schema_version, canonical_path)?.as_bytes())
}

fn to_semver(version: &VersionSpec) -> jw_guard_core::SemVer {
    jw_guard_core::SemVer::new(version.major, version.minor, version.patch)
}

fn requirement_value(value: &RequirementValueSpec) -> Result<RequirementValue, DeclareError> {
    Ok(match value {
        RequirementValueSpec::Bool(item) => RequirementValue::Bool(*item),
        RequirementValueSpec::U64(item) => RequirementValue::U64(*item),
        RequirementValueSpec::Name(item) => RequirementValue::Name(CanonicalName::new(item.as_str().into())?),
        RequirementValueSpec::Names(items) => RequirementValue::Names(
            items
                .iter()
                .map(|item| CanonicalName::new(item.as_str().into()))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        RequirementValueSpec::DurationSeconds(item) => RequirementValue::DurationSeconds(*item),
    })
}

#[cfg(test)]
mod tests {
    use super::concretise;
    use crate::{
        ActorSpec, BoundarySpec, DeclaredSpec, EdgeSpec, ModelSpec, PolicySpec, ReferentSpec,
        RequirementSpec, RequirementValueSpec, ScopePredicateSpec, ScopeSpec, SymbolicName, VersionSpec,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use jw_guard_core::{Direction, RequirementOperator};

    fn name(value: &str) -> SymbolicName {
        SymbolicName::new(value).expect("test names should be valid")
    }

    fn sample_spec() -> DeclaredSpec {
        DeclaredSpec {
            schema_version: name("v1"),
            model: ModelSpec {
                name: name("security"),
                version: VersionSpec {
                    major: 1,
                    minor: 2,
                    patch: 3,
                },
                declared_at_unix_seconds: 1_700_000_000,
                declared_by: name("owner"),
            },
            actors: vec![
                ActorSpec {
                    name: name("service"),
                    role: name("workload"),
                },
                ActorSpec {
                    name: name("owner"),
                    role: name("operator"),
                },
            ],
            referents: vec![
                ReferentSpec {
                    name: name("database"),
                    sort: 2,
                },
                ReferentSpec {
                    name: name("frontend"),
                    sort: 1,
                },
            ],
            boundaries: vec![BoundarySpec {
                name: name("public"),
                side_a_anchor: name("frontend"),
                side_b_anchor: name("database"),
            }],
            edges: vec![EdgeSpec {
                name: name("calls"),
                sort: 3,
                direction: Direction::Directed,
                first: name("frontend"),
                second: name("database"),
            }],
            scopes: vec![ScopeSpec {
                name: name("external"),
                referent_sort: 1,
                snapshot_unix_seconds: 1_700_000_050,
                namespace: name("prod"),
                mapper_version: VersionSpec {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                predicate: ScopePredicateSpec::NameEquals(name("frontend")),
            }],
            requirements: vec![RequirementSpec {
                name: name("minimum"),
                sort: 1,
                operator: RequirementOperator::CountMin,
                value: RequirementValueSpec::U64(1),
            }],
            policies: vec![PolicySpec {
                name: name("runtime"),
                declared_by: name("owner"),
                scope: name("external"),
                requirement: name("minimum"),
            }],
        }
    }

    #[test]
    fn concretise_is_deterministic_and_paths_are_sorted() {
        let spec = sample_spec();
        let first = concretise(&spec).expect("concretise should succeed");
        let second = concretise(&spec).expect("concretise should succeed");

        assert_eq!(first.model.id, second.model.id);
        assert_eq!(first.actors[0].id, second.actors[0].id);
        assert_eq!(
            first.canonical_paths.actors,
            vec!["actor/owner".to_string(), "actor/service".to_string()]
        );
        assert_eq!(
            first.canonical_paths.referents,
            vec!["referent/database".to_string(), "referent/frontend".to_string()]
        );
    }

    #[test]
    fn concretise_builds_expected_output_shape() {
        let model = concretise(&sample_spec()).expect("concretise should succeed");
        assert_eq!(model.actors.len(), 2);
        assert_eq!(model.referents.len(), 2);
        assert_eq!(model.boundaries.len(), 1);
        assert_eq!(model.edges.len(), 1);
        assert_eq!(model.scopes.len(), 1);
        assert_eq!(model.requirements.len(), 1);
        assert_eq!(model.policies.len(), 1);
        assert_eq!(model.canonical_paths.model, "model/security");
    }
}
