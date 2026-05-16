use jw_guard_core::{Direction, RequirementOperator};
use jw_guard_declare::{
    ActorSpec, BoundarySpec, DeclaredSpec, DeclareError, EdgeSpec, ModelSpec, PolicySpec, ReferentSpec,
    RequirementSpec, RequirementValueSpec, ScopePredicateSpec, ScopeSpec, SymbolicName, SymbolicNameError,
    VersionSpec,
};

use crate::dto::{
    WireActorSpec, WireBoundarySpec, WireDeclaredSpec, WireDirection, WireEdgeSpec, WireModelSpec, WirePolicySpec,
    WireReferentSpec, WireRequirementOperator, WireRequirementSpec, WireRequirementValueSpec, WireScopePredicateSpec,
    WireScopeSpec, WireVersionSpec,
};

impl TryFrom<WireDeclaredSpec> for DeclaredSpec {
    type Error = Vec<DeclareError>;

    fn try_from(value: WireDeclaredSpec) -> Result<Self, Self::Error> {
        let mut errors = Vec::new();

        let schema_version = parse_name("schema_version", value.schema_version, &mut errors);
        let model = convert_model(value.model, &mut errors);
        let actors = value
            .actors
            .into_iter()
            .enumerate()
            .map(|(index, actor)| convert_actor(index, actor, &mut errors))
            .collect();
        let referents = value
            .referents
            .into_iter()
            .enumerate()
            .map(|(index, referent)| convert_referent(index, referent, &mut errors))
            .collect();
        let boundaries = value
            .boundaries
            .into_iter()
            .enumerate()
            .map(|(index, boundary)| convert_boundary(index, boundary, &mut errors))
            .collect();
        let edges = value
            .edges
            .into_iter()
            .enumerate()
            .map(|(index, edge)| convert_edge(index, edge, &mut errors))
            .collect();
        let scopes = value
            .scopes
            .into_iter()
            .enumerate()
            .map(|(index, scope)| convert_scope(index, scope, &mut errors))
            .collect();
        let requirements = value
            .requirements
            .into_iter()
            .enumerate()
            .map(|(index, requirement)| convert_requirement(index, requirement, &mut errors))
            .collect();
        let policies = value
            .policies
            .into_iter()
            .enumerate()
            .map(|(index, policy)| convert_policy(index, policy, &mut errors))
            .collect();

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(DeclaredSpec {
            schema_version: schema_version.expect("schema_version should be present without errors"),
            model: model.expect("model should be present without errors"),
            actors,
            referents,
            boundaries,
            edges,
            scopes,
            requirements,
            policies,
        })
    }
}

fn convert_model(model: WireModelSpec, errors: &mut Vec<DeclareError>) -> Option<ModelSpec> {
    let name = parse_name("model.name", model.name, errors);
    let declared_by = parse_name("model.declared_by", model.declared_by, errors);

    if name.is_none() || declared_by.is_none() {
        return None;
    }

    Some(ModelSpec {
        name: name.expect("name checked"),
        version: convert_version(model.version),
        declared_at_unix_seconds: model.declared_at_unix_seconds,
        declared_by: declared_by.expect("declared_by checked"),
    })
}

fn convert_actor(index: usize, actor: WireActorSpec, errors: &mut Vec<DeclareError>) -> ActorSpec {
    ActorSpec {
        name: parse_name_with_index("actors", index, "name", actor.name, errors),
        role: parse_name_with_index("actors", index, "role", actor.role, errors),
    }
}

fn convert_referent(index: usize, referent: WireReferentSpec, errors: &mut Vec<DeclareError>) -> ReferentSpec {
    ReferentSpec {
        name: parse_name_with_index("referents", index, "name", referent.name, errors),
        sort: referent.sort,
    }
}

fn convert_boundary(index: usize, boundary: WireBoundarySpec, errors: &mut Vec<DeclareError>) -> BoundarySpec {
    BoundarySpec {
        name: parse_name_with_index("boundaries", index, "name", boundary.name, errors),
        side_a_anchor: parse_name_with_index("boundaries", index, "side_a_anchor", boundary.side_a_anchor, errors),
        side_b_anchor: parse_name_with_index("boundaries", index, "side_b_anchor", boundary.side_b_anchor, errors),
    }
}

fn convert_edge(index: usize, edge: WireEdgeSpec, errors: &mut Vec<DeclareError>) -> EdgeSpec {
    EdgeSpec {
        name: parse_name_with_index("edges", index, "name", edge.name, errors),
        sort: edge.sort,
        direction: convert_direction(edge.direction),
        first: parse_name_with_index("edges", index, "first", edge.first, errors),
        second: parse_name_with_index("edges", index, "second", edge.second, errors),
    }
}

fn convert_scope(index: usize, scope: WireScopeSpec, errors: &mut Vec<DeclareError>) -> ScopeSpec {
    ScopeSpec {
        name: parse_name_with_index("scopes", index, "name", scope.name, errors),
        referent_sort: scope.referent_sort,
        snapshot_unix_seconds: scope.snapshot_unix_seconds,
        namespace: parse_name_with_index("scopes", index, "namespace", scope.namespace, errors),
        mapper_version: convert_version(scope.mapper_version),
        predicate: convert_scope_predicate(index, scope.predicate, errors),
    }
}

fn convert_scope_predicate(
    index: usize,
    predicate: WireScopePredicateSpec,
    errors: &mut Vec<DeclareError>,
) -> ScopePredicateSpec {
    match predicate {
        WireScopePredicateSpec::All => ScopePredicateSpec::All,
        WireScopePredicateSpec::HasTag { tag } => {
            ScopePredicateSpec::HasTag(parse_name_with_index("scopes", index, "predicate.tag", tag, errors))
        }
        WireScopePredicateSpec::NameEquals { name } => {
            ScopePredicateSpec::NameEquals(parse_name_with_index("scopes", index, "predicate.name", name, errors))
        }
    }
}

fn convert_requirement(
    index: usize,
    requirement: WireRequirementSpec,
    errors: &mut Vec<DeclareError>,
) -> RequirementSpec {
    RequirementSpec {
        name: parse_name_with_index("requirements", index, "name", requirement.name, errors),
        sort: requirement.sort,
        operator: convert_operator(requirement.operator),
        value: convert_requirement_value(index, requirement.value, errors),
    }
}

fn convert_requirement_value(
    index: usize,
    value: WireRequirementValueSpec,
    errors: &mut Vec<DeclareError>,
) -> RequirementValueSpec {
    match value {
        WireRequirementValueSpec::Bool { value } => RequirementValueSpec::Bool(value),
        WireRequirementValueSpec::U64 { value } => RequirementValueSpec::U64(value),
        WireRequirementValueSpec::Name { name } => {
            RequirementValueSpec::Name(parse_name_with_index("requirements", index, "value.name", name, errors))
        }
        WireRequirementValueSpec::Names { names } => RequirementValueSpec::Names(
            names
                .into_iter()
                .enumerate()
                .map(|(name_index, name)| {
                    parse_name_with_path(
                        format!("requirements[{index}].value.names[{name_index}]"),
                        name,
                        errors,
                    )
                })
                .collect(),
        ),
        WireRequirementValueSpec::DurationSeconds { seconds } => RequirementValueSpec::DurationSeconds(seconds),
    }
}

fn convert_policy(index: usize, policy: WirePolicySpec, errors: &mut Vec<DeclareError>) -> PolicySpec {
    PolicySpec {
        name: parse_name_with_index("policies", index, "name", policy.name, errors),
        declared_by: parse_name_with_index("policies", index, "declared_by", policy.declared_by, errors),
        scope: parse_name_with_index("policies", index, "scope", policy.scope, errors),
        requirement: parse_name_with_index("policies", index, "requirement", policy.requirement, errors),
    }
}

fn convert_version(version: WireVersionSpec) -> VersionSpec {
    VersionSpec {
        major: version.major,
        minor: version.minor,
        patch: version.patch,
    }
}

fn convert_direction(direction: WireDirection) -> Direction {
    match direction {
        WireDirection::Directed => Direction::Directed,
        WireDirection::Undirected => Direction::Undirected,
    }
}

fn convert_operator(operator: WireRequirementOperator) -> RequirementOperator {
    match operator {
        WireRequirementOperator::PresenceRequired => RequirementOperator::PresenceRequired,
        WireRequirementOperator::PresenceForbidden => RequirementOperator::PresenceForbidden,
        WireRequirementOperator::PresenceOptional => RequirementOperator::PresenceOptional,
        WireRequirementOperator::CountEqual => RequirementOperator::CountEqual,
        WireRequirementOperator::CountMin => RequirementOperator::CountMin,
        WireRequirementOperator::CountMax => RequirementOperator::CountMax,
        WireRequirementOperator::SetIncludes => RequirementOperator::SetIncludes,
        WireRequirementOperator::SetExcludes => RequirementOperator::SetExcludes,
        WireRequirementOperator::SetEquals => RequirementOperator::SetEquals,
        WireRequirementOperator::TemporalBefore => RequirementOperator::TemporalBefore,
        WireRequirementOperator::TemporalAfter => RequirementOperator::TemporalAfter,
        WireRequirementOperator::TemporalWithin => RequirementOperator::TemporalWithin,
        WireRequirementOperator::RelationExists => RequirementOperator::RelationExists,
        WireRequirementOperator::RelationNotExists => RequirementOperator::RelationNotExists,
        WireRequirementOperator::RelationPathLengthMax => RequirementOperator::RelationPathLengthMax,
        WireRequirementOperator::RelationEdgeCountMax => RequirementOperator::RelationEdgeCountMax,
    }
}

fn parse_name_with_index(
    section: &str,
    index: usize,
    field: &str,
    value: String,
    errors: &mut Vec<DeclareError>,
) -> SymbolicName {
    parse_name_with_path(format!("{section}[{index}].{field}"), value, errors)
}

fn parse_name(path: &str, value: String, errors: &mut Vec<DeclareError>) -> Option<SymbolicName> {
    SymbolicName::new(&value).map_or_else(
        |source| {
            errors.push(symbolic_name_error(path.to_owned(), value, source));
            None
        },
        Some,
    )
}

fn parse_name_with_path(path: String, value: String, errors: &mut Vec<DeclareError>) -> SymbolicName {
    SymbolicName::new(&value).unwrap_or_else(|source| {
        errors.push(symbolic_name_error(path, value, source));
        SymbolicName::new("invalid").expect("hardcoded symbolic name is valid")
    })
}

fn symbolic_name_error(path: String, value: String, source: SymbolicNameError) -> DeclareError {
    DeclareError::InvalidSymbolicName {
        path,
        value,
        source,
    }
}
