use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use jw_guard_core::{Direction, RequirementOperator};
use jw_guard_declare::{
    EdgeSpec, PolicySpec, ReferentSpec, RequirementSpec, RequirementValueSpec, ScopePredicateSpec, ScopeSpec,
    SymbolicName, VersionSpec,
};
use jw_guard_policy_schema::{
    EdgeBudgetPolicyDocument, PhaseSeparationPolicyDocument, PolicyDocument, PolicyEnvelope, PolicyKind,
    PortProfilePolicyDocument, ScopePolicyDocument, TransportRoutesPolicyDocument,
};

use crate::PolicyCompileError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompiledPolicyFragment {
    pub scopes: Vec<ScopeSpec>,
    pub requirements: Vec<RequirementSpec>,
    pub policies: Vec<PolicySpec>,
    pub referents: Vec<ReferentSpec>,
    pub edges: Vec<EdgeSpec>,
}

pub fn compile_document(document: &PolicyDocument) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let mut fragment = match document {
        PolicyDocument::ScopePolicy(policy) => compile_scope_policy(policy)?,
        PolicyDocument::PhaseSeparationPolicy(policy) => compile_phase_separation_policy(policy)?,
        PolicyDocument::EdgeBudgetPolicy(policy) => compile_edge_budget_policy(policy)?,
        PolicyDocument::PortProfilePolicy(policy) => compile_port_profile_policy(policy)?,
        PolicyDocument::TransportRoutesPolicy(policy) => compile_transport_routes_policy(policy)?,
    };

    sort_fragment(&mut fragment);
    Ok(fragment)
}

pub fn merge_compiled_fragments(
    fragments: &[CompiledPolicyFragment],
) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let mut scopes = Vec::new();
    let mut requirements = Vec::new();
    let mut policies = Vec::new();
    let mut referents = Vec::new();
    let mut edges = Vec::new();

    for fragment in fragments {
        scopes.extend(fragment.scopes.clone());
        requirements.extend(fragment.requirements.clone());
        policies.extend(fragment.policies.clone());
        referents.extend(fragment.referents.clone());
        edges.extend(fragment.edges.clone());
    }

    Ok(CompiledPolicyFragment {
        scopes: merge_named(scopes, "scopes", |item| &item.name)?,
        requirements: merge_named(requirements, "requirements", |item| &item.name)?,
        policies: merge_named(policies, "policies", |item| &item.name)?,
        referents: merge_named(referents, "referents", |item| &item.name)?,
        edges: merge_named(edges, "edges", |item| &item.name)?,
    })
}

fn merge_named<T, F>(
    mut items: Vec<T>,
    section: &'static str,
    name_of: F,
) -> Result<Vec<T>, PolicyCompileError>
where
    T: Clone + Eq,
    F: Fn(&T) -> &SymbolicName,
{
    items.sort_by(|a, b| name_of(a).cmp(name_of(b)));

    let mut deduped = Vec::new();
    for item in items {
        if let Some(previous) = deduped.last() {
            if name_of(previous) == name_of(&item) {
                if previous != &item {
                    return Err(PolicyCompileError::ConflictingDuplicate {
                        section,
                        name: name_of(&item).to_string(),
                    });
                }
                continue;
            }
        }

        deduped.push(item);
    }

    Ok(deduped)
}

fn compile_scope_policy(document: &ScopePolicyDocument) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let expected = PolicyKind::ScopePolicy;
    assert_expected_kind(document.kind, expected)?;
    ensure_non_empty_requirements(expected, &document.metadata.name, document.requirements.len())?;

    let scope_name = name("scope.name", &format!("scope-policy-{}-scope", document.metadata.name))?;
    let declared_by = name("policy.declared_by", &document.metadata.name)?;
    let mapper_version = parse_version(&document.metadata.version)?;
    let namespace = name("scope.namespace", "policy-scope-policy")?;
    let predicate = ScopePredicateSpec::HasTag(name(
        "scope.predicate",
        &format!("target-{}", scope_target_token(document.scope.target)),
    )?);
    let referent_sort = policy_referent_sort(expected);

    let mut fragment = base_fragment(
        scope_name.clone(),
        referent_sort,
        namespace,
        mapper_version,
        predicate,
        declared_by.clone(),
    );

    for (index, requirement) in document.requirements.iter().enumerate() {
        let requirement_name = name(
            "requirement.name",
            &format!(
                "scope-policy-{}-requirement-{index:03}",
                document.metadata.name
            ),
        )?;
        let policy_name = name(
            "policy.name",
            &format!("scope-policy-{}-policy-{index:03}", document.metadata.name),
        )?;

        let selector_name = name(
            "requirement.value",
            &format!("selector-{}", scope_selector_token(requirement.selector)),
        )?;
        let operator = match requirement.constraint {
            jw_guard_policy_schema::ScopeConstraint::InScope => RequirementOperator::PresenceRequired,
            jw_guard_policy_schema::ScopeConstraint::OutOfScope => RequirementOperator::PresenceForbidden,
        };

        fragment.requirements.push(RequirementSpec {
            name: requirement_name.clone(),
            sort: u16::try_from(index + 1).unwrap_or(u16::MAX),
            operator,
            value: RequirementValueSpec::Name(selector_name),
        });

        fragment.policies.push(PolicySpec {
            name: policy_name,
            declared_by: declared_by.clone(),
            scope: scope_name.clone(),
            requirement: requirement_name,
        });
    }

    append_explicit_declarations(&mut fragment, document)?;
    Ok(fragment)
}

fn compile_phase_separation_policy(
    document: &PhaseSeparationPolicyDocument,
) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let expected = PolicyKind::PhaseSeparationPolicy;
    assert_expected_kind(document.kind, expected)?;
    ensure_non_empty_requirements(expected, &document.metadata.name, document.requirements.len())?;

    let scope_name = name(
        "scope.name",
        &format!("phase-separation-{}-scope", document.metadata.name),
    )?;
    let declared_by = name("policy.declared_by", &document.metadata.name)?;
    let mapper_version = parse_version(&document.metadata.version)?;
    let namespace = name("scope.namespace", "policy-phase-separation")?;
    let predicate = ScopePredicateSpec::HasTag(name(
        "scope.predicate",
        &format!(
            "lifecycle-{}",
            phase_lifecycle_token(document.scope.lifecycle)
        ),
    )?);
    let referent_sort = policy_referent_sort(expected);

    let mut fragment = base_fragment(
        scope_name.clone(),
        referent_sort,
        namespace,
        mapper_version,
        predicate,
        declared_by.clone(),
    );

    for (index, requirement) in document.requirements.iter().enumerate() {
        let requirement_name = name(
            "requirement.name",
            &format!(
                "phase-separation-{}-requirement-{index:03}",
                document.metadata.name
            ),
        )?;
        let policy_name = name(
            "policy.name",
            &format!("phase-separation-{}-policy-{index:03}", document.metadata.name),
        )?;

        let relation_name = name(
            "requirement.value",
            &format!(
                "phase-{}-to-{}",
                phase_name_token(requirement.producer),
                phase_name_token(requirement.consumer)
            ),
        )?;
        let operator = match requirement.relation {
            jw_guard_policy_schema::PhaseRelation::Isolated => RequirementOperator::RelationNotExists,
            jw_guard_policy_schema::PhaseRelation::ReadOnlyHandoff => RequirementOperator::RelationExists,
        };

        fragment.requirements.push(RequirementSpec {
            name: requirement_name.clone(),
            sort: u16::try_from(index + 1).unwrap_or(u16::MAX),
            operator,
            value: RequirementValueSpec::Name(relation_name),
        });

        fragment.policies.push(PolicySpec {
            name: policy_name,
            declared_by: declared_by.clone(),
            scope: scope_name.clone(),
            requirement: requirement_name,
        });
    }

    append_explicit_declarations(&mut fragment, document)?;
    Ok(fragment)
}

fn compile_edge_budget_policy(
    document: &EdgeBudgetPolicyDocument,
) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let expected = PolicyKind::EdgeBudgetPolicy;
    assert_expected_kind(document.kind, expected)?;
    ensure_non_empty_requirements(expected, &document.metadata.name, document.requirements.len())?;

    let scope_name = name("scope.name", &format!("edge-budget-{}-scope", document.metadata.name))?;
    let declared_by = name("policy.declared_by", &document.metadata.name)?;
    let mapper_version = parse_version(&document.metadata.version)?;
    let namespace = name("scope.namespace", "policy-edge-budget")?;
    let predicate = ScopePredicateSpec::HasTag(name(
        "scope.predicate",
        &format!("graph-{}", graph_kind_token(document.scope.graph)),
    )?);
    let referent_sort = policy_referent_sort(expected);

    let mut fragment = base_fragment(
        scope_name.clone(),
        referent_sort,
        namespace,
        mapper_version,
        predicate,
        declared_by.clone(),
    );

    for (index, requirement) in document.requirements.iter().enumerate() {
        let requirement_name = name(
            "requirement.name",
            &format!("edge-budget-{}-requirement-{index:03}", document.metadata.name),
        )?;
        let policy_name = name(
            "policy.name",
            &format!("edge-budget-{}-policy-{index:03}", document.metadata.name),
        )?;

        fragment.requirements.push(RequirementSpec {
            name: requirement_name.clone(),
            sort: u16::try_from(index + 1).unwrap_or(u16::MAX),
            operator: RequirementOperator::RelationEdgeCountMax,
            value: RequirementValueSpec::U64(u64::from(requirement.max_edges)),
        });

        fragment.policies.push(PolicySpec {
            name: policy_name,
            declared_by: declared_by.clone(),
            scope: scope_name.clone(),
            requirement: requirement_name,
        });
    }

    append_explicit_declarations(&mut fragment, document)?;
    Ok(fragment)
}

fn compile_port_profile_policy(
    document: &PortProfilePolicyDocument,
) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let expected = PolicyKind::PortProfilePolicy;
    assert_expected_kind(document.kind, expected)?;
    ensure_non_empty_requirements(expected, &document.metadata.name, document.requirements.len())?;

    let scope_name = name(
        "scope.name",
        &format!("port-profile-{}-scope", document.metadata.name),
    )?;
    let declared_by = name("policy.declared_by", &document.metadata.name)?;
    let mapper_version = parse_version(&document.metadata.version)?;
    let namespace = name("scope.namespace", "policy-port-profile")?;
    let predicate = ScopePredicateSpec::HasTag(name(
        "scope.predicate",
        &format!("environment-{}", port_environment_token(document.scope.environment)),
    )?);
    let referent_sort = policy_referent_sort(expected);

    let mut fragment = base_fragment(
        scope_name.clone(),
        referent_sort,
        namespace,
        mapper_version,
        predicate,
        declared_by.clone(),
    );

    for (index, requirement) in document.requirements.iter().enumerate() {
        let requirement_name = name(
            "requirement.name",
            &format!("port-profile-{}-requirement-{index:03}", document.metadata.name),
        )?;
        let policy_name = name(
            "policy.name",
            &format!("port-profile-{}-policy-{index:03}", document.metadata.name),
        )?;

        fragment.requirements.push(RequirementSpec {
            name: requirement_name.clone(),
            sort: u16::try_from(index + 1).unwrap_or(u16::MAX),
            operator: RequirementOperator::CountEqual,
            value: RequirementValueSpec::U64(u64::from(requirement.port)),
        });

        fragment.policies.push(PolicySpec {
            name: policy_name,
            declared_by: declared_by.clone(),
            scope: scope_name.clone(),
            requirement: requirement_name,
        });
    }

    append_explicit_declarations(&mut fragment, document)?;
    Ok(fragment)
}

fn compile_transport_routes_policy(
    document: &TransportRoutesPolicyDocument,
) -> Result<CompiledPolicyFragment, PolicyCompileError> {
    let expected = PolicyKind::TransportRoutesPolicy;
    assert_expected_kind(document.kind, expected)?;
    ensure_non_empty_requirements(expected, &document.metadata.name, document.requirements.len())?;

    let scope_name = name(
        "scope.name",
        &format!("transport-routes-{}-scope", document.metadata.name),
    )?;
    let declared_by = name("policy.declared_by", &document.metadata.name)?;
    let mapper_version = parse_version(&document.metadata.version)?;
    let namespace = name("scope.namespace", "policy-transport-routes")?;
    let predicate = ScopePredicateSpec::HasTag(name(
        "scope.predicate",
        &format!("topology-{}", route_topology_token(document.scope.topology)),
    )?);
    let referent_sort = policy_referent_sort(expected);

    let mut fragment = base_fragment(
        scope_name.clone(),
        referent_sort,
        namespace,
        mapper_version,
        predicate,
        declared_by.clone(),
    );

    for (index, requirement) in document.requirements.iter().enumerate() {
        let requirement_name = name(
            "requirement.name",
            &format!(
                "transport-routes-{}-requirement-{index:03}",
                document.metadata.name
            ),
        )?;
        let policy_name = name(
            "policy.name",
            &format!("transport-routes-{}-policy-{index:03}", document.metadata.name),
        )?;

        let route_name = name(
            "requirement.value",
            &format!(
                "route-{}-to-{}-via-{}",
                route_endpoint_token(requirement.from),
                route_endpoint_token(requirement.to),
                transport_protocol_token(requirement.transport)
            ),
        )?;
        let operator = match requirement.action {
            jw_guard_policy_schema::RouteAction::Allow => RequirementOperator::RelationExists,
            jw_guard_policy_schema::RouteAction::Deny => RequirementOperator::RelationNotExists,
        };

        fragment.requirements.push(RequirementSpec {
            name: requirement_name.clone(),
            sort: u16::try_from(index + 1).unwrap_or(u16::MAX),
            operator,
            value: RequirementValueSpec::Name(route_name),
        });

        fragment.policies.push(PolicySpec {
            name: policy_name,
            declared_by: declared_by.clone(),
            scope: scope_name.clone(),
            requirement: requirement_name,
        });
    }

    append_explicit_declarations(&mut fragment, document)?;
    Ok(fragment)
}

fn base_fragment(
    scope_name: SymbolicName,
    referent_sort: u16,
    namespace: SymbolicName,
    mapper_version: VersionSpec,
    predicate: ScopePredicateSpec,
    _declared_by: SymbolicName,
) -> CompiledPolicyFragment {
    CompiledPolicyFragment {
        scopes: vec![ScopeSpec {
            name: scope_name,
            referent_sort,
            snapshot_unix_seconds: 0,
            namespace,
            mapper_version,
            predicate,
        }],
        requirements: Vec::new(),
        policies: Vec::new(),
        referents: Vec::new(),
        edges: Vec::new(),
    }
}

fn append_explicit_declarations<S, R>(
    fragment: &mut CompiledPolicyFragment,
    document: &PolicyEnvelope<S, R>,
) -> Result<(), PolicyCompileError> {
    for referent in &document.declarations.referents {
        fragment.referents.push(ReferentSpec {
            name: name("declarations.referents.name", &referent.name)?,
            sort: referent.sort,
        });
    }

    for edge in &document.declarations.edges {
        fragment.edges.push(EdgeSpec {
            name: name("declarations.edges.name", &edge.name)?,
            sort: edge.sort,
            direction: match edge.direction {
                jw_guard_policy_schema::EdgeDirection::Directed => Direction::Directed,
                jw_guard_policy_schema::EdgeDirection::Undirected => Direction::Undirected,
            },
            first: name("declarations.edges.first", &edge.first)?,
            second: name("declarations.edges.second", &edge.second)?,
        });
    }

    Ok(())
}

fn assert_expected_kind(found: PolicyKind, expected: PolicyKind) -> Result<(), PolicyCompileError> {
    if found == expected {
        return Ok(());
    }

    Err(PolicyCompileError::InconsistentPolicyKind { expected, found })
}

fn ensure_non_empty_requirements(
    kind: PolicyKind,
    policy_name: &str,
    requirement_count: usize,
) -> Result<(), PolicyCompileError> {
    if requirement_count > 0 {
        return Ok(());
    }

    Err(PolicyCompileError::EmptyRequirements {
        kind,
        policy_name: policy_name.to_string(),
    })
}

fn name(field: &'static str, value: &str) -> Result<SymbolicName, PolicyCompileError> {
    SymbolicName::new(value).map_err(|source| PolicyCompileError::InvalidSymbolicName {
        field,
        value: value.to_string(),
        source,
    })
}

fn parse_version(value: &str) -> Result<VersionSpec, PolicyCompileError> {
    let mut pieces = value.split('.');
    let major = parse_u16_piece(pieces.next(), value)?;
    let minor = parse_u16_piece(pieces.next(), value)?;
    let patch = parse_u16_piece(pieces.next(), value)?;

    if pieces.next().is_some() {
        return Err(PolicyCompileError::InvalidVersion {
            value: value.to_string(),
        });
    }

    Ok(VersionSpec {
        major,
        minor,
        patch,
    })
}

fn parse_u16_piece(piece: Option<&str>, full_value: &str) -> Result<u16, PolicyCompileError> {
    let Some(piece) = piece else {
        return Err(PolicyCompileError::InvalidVersion {
            value: full_value.to_string(),
        });
    };

    piece
        .parse::<u16>()
        .map_err(|_| PolicyCompileError::InvalidVersion {
            value: full_value.to_string(),
        })
}

fn policy_referent_sort(kind: PolicyKind) -> u16 {
    match kind {
        PolicyKind::ScopePolicy => 101,
        PolicyKind::PhaseSeparationPolicy => 102,
        PolicyKind::EdgeBudgetPolicy => 103,
        PolicyKind::PortProfilePolicy => 104,
        PolicyKind::TransportRoutesPolicy => 105,
    }
}

fn sort_fragment(fragment: &mut CompiledPolicyFragment) {
    fragment.scopes.sort_by(|a, b| a.name.cmp(&b.name));
    fragment.requirements.sort_by(|a, b| a.name.cmp(&b.name));
    fragment.policies.sort_by(|a, b| a.name.cmp(&b.name));
    fragment.referents.sort_by(|a, b| a.name.cmp(&b.name));
    fragment.edges.sort_by(|a, b| a.name.cmp(&b.name));
}

fn scope_target_token(value: jw_guard_policy_schema::ScopeTarget) -> &'static str {
    match value {
        jw_guard_policy_schema::ScopeTarget::Workspace => "workspace",
        jw_guard_policy_schema::ScopeTarget::Package => "package",
        jw_guard_policy_schema::ScopeTarget::Artifact => "artifact",
    }
}

fn scope_selector_token(value: jw_guard_policy_schema::ScopeSelector) -> &'static str {
    match value {
        jw_guard_policy_schema::ScopeSelector::Source => "source",
        jw_guard_policy_schema::ScopeSelector::Build => "build",
        jw_guard_policy_schema::ScopeSelector::Runtime => "runtime",
    }
}

fn phase_lifecycle_token(value: jw_guard_policy_schema::PhaseLifecycle) -> &'static str {
    match value {
        jw_guard_policy_schema::PhaseLifecycle::BuildRuntime => "build-runtime",
        jw_guard_policy_schema::PhaseLifecycle::RuntimeOperations => "runtime-operations",
    }
}

fn phase_name_token(value: jw_guard_policy_schema::PhaseName) -> &'static str {
    match value {
        jw_guard_policy_schema::PhaseName::Build => "build",
        jw_guard_policy_schema::PhaseName::Sign => "sign",
        jw_guard_policy_schema::PhaseName::Release => "release",
        jw_guard_policy_schema::PhaseName::Runtime => "runtime",
    }
}

fn graph_kind_token(value: jw_guard_policy_schema::GraphKind) -> &'static str {
    match value {
        jw_guard_policy_schema::GraphKind::Dependency => "dependency",
        jw_guard_policy_schema::GraphKind::RuntimeCall => "runtime-call",
    }
}

fn port_environment_token(value: jw_guard_policy_schema::PortEnvironment) -> &'static str {
    match value {
        jw_guard_policy_schema::PortEnvironment::Development => "development",
        jw_guard_policy_schema::PortEnvironment::Staging => "staging",
        jw_guard_policy_schema::PortEnvironment::Production => "production",
    }
}

fn route_topology_token(value: jw_guard_policy_schema::RouteTopology) -> &'static str {
    match value {
        jw_guard_policy_schema::RouteTopology::Cluster => "cluster",
        jw_guard_policy_schema::RouteTopology::Mesh => "mesh",
    }
}

fn route_endpoint_token(value: jw_guard_policy_schema::RouteEndpoint) -> &'static str {
    match value {
        jw_guard_policy_schema::RouteEndpoint::Runtime => "runtime",
        jw_guard_policy_schema::RouteEndpoint::ControlPlane => "control-plane",
        jw_guard_policy_schema::RouteEndpoint::AuditSink => "audit-sink",
    }
}

fn transport_protocol_token(value: jw_guard_policy_schema::TransportProtocol) -> &'static str {
    match value {
        jw_guard_policy_schema::TransportProtocol::Tcp => "tcp",
        jw_guard_policy_schema::TransportProtocol::Udp => "udp",
        jw_guard_policy_schema::TransportProtocol::Http => "http",
        jw_guard_policy_schema::TransportProtocol::Https => "https",
        jw_guard_policy_schema::TransportProtocol::Grpc => "grpc",
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use jw_guard_core::RequirementOperator;
    use jw_guard_declare::{RequirementValueSpec, ScopePredicateSpec, SymbolicName};
    use jw_guard_policy_schema::{
        ApiVersion, EdgeBudgetPolicyScope, EdgeBudgetRequirement, GraphKind, PhaseLifecycle, PhaseName,
        PhaseRelation, PhaseSeparationPolicyScope, PhaseSeparationRequirement, PolicyDeclarations, PolicyDocument,
        PolicyEnvelope, PolicyKind, PolicyMetadata, PortEnvironment, PortProfile, PortProfilePolicyScope,
        PortProfileRequirement, PortExposure, RouteAction, RouteEndpoint, RouteTopology, ScopeConstraint,
        ScopePolicyDocument, ScopePolicyRequirement, ScopePolicyScope, ScopeSelector, ScopeTarget,
        TransportProtocol, TransportRouteRequirement, TransportRoutesPolicyScope,
    };

    use super::{compile_document, merge_compiled_fragments};

    #[test]
    fn compile_output_is_deterministic_for_same_input() {
        let document = scope_document();

        let first = compile_document(&document).expect("compile should succeed");
        let second = compile_document(&document).expect("compile should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn merge_detects_conflicting_duplicates() {
        let base = compile_document(&scope_document()).expect("compile should succeed");
        let mut conflicting = base.clone();
        conflicting.scopes[0].referent_sort = 9_999;

        let error =
            merge_compiled_fragments(&[base, conflicting]).expect_err("merge should detect conflict");
        assert!(matches!(
            error,
            crate::PolicyCompileError::ConflictingDuplicate { section: "scopes", .. }
        ));
    }

    #[test]
    fn compile_first_five_policy_kinds_into_expected_fragments() {
        let cases = [
            (
                scope_document(),
                RequirementOperator::PresenceRequired,
                RequirementValueSpec::Name(name("selector-source")),
            ),
            (
                phase_document(),
                RequirementOperator::RelationNotExists,
                RequirementValueSpec::Name(name("phase-build-to-sign")),
            ),
            (
                edge_budget_document(),
                RequirementOperator::RelationEdgeCountMax,
                RequirementValueSpec::U64(4),
            ),
            (
                port_profile_document(),
                RequirementOperator::CountEqual,
                RequirementValueSpec::U64(9443),
            ),
            (
                transport_routes_document(),
                RequirementOperator::RelationExists,
                RequirementValueSpec::Name(name("route-runtime-to-control-plane-via-grpc")),
            ),
        ];

        for (document, expected_operator, expected_value) in cases {
            let fragment = compile_document(&document).expect("compile should succeed");
            assert_eq!(fragment.scopes.len(), 1);
            assert_eq!(fragment.requirements.len(), 1);
            assert_eq!(fragment.policies.len(), 1);
            assert_eq!(fragment.requirements[0].operator, expected_operator);
            assert_eq!(fragment.requirements[0].value, expected_value);
            assert!(matches!(
                fragment.scopes[0].predicate,
                ScopePredicateSpec::HasTag(_)
            ));
        }
    }

    #[test]
    fn compile_emits_explicit_declarations_only_when_present() {
        let document = scope_document();
        let fragment = compile_document(&document).expect("compile should succeed");
        assert!(fragment.referents.is_empty());
        assert!(fragment.edges.is_empty());

        let mut with_declarations = scope_policy_envelope();
        with_declarations.declarations = PolicyDeclarations {
            referents: vec![jw_guard_policy_schema::ReferentDeclaration {
                name: "runtime".into(),
                sort: 1,
            }],
            edges: vec![jw_guard_policy_schema::EdgeDeclaration {
                name: "runtime-calls-audit".into(),
                sort: 1,
                direction: jw_guard_policy_schema::EdgeDirection::Directed,
                first: "runtime".into(),
                second: "audit".into(),
            }],
        };

        let fragment_with_declarations =
            compile_document(&PolicyDocument::ScopePolicy(with_declarations))
                .expect("compile should succeed");
        assert_eq!(fragment_with_declarations.referents.len(), 1);
        assert_eq!(fragment_with_declarations.edges.len(), 1);
    }

    fn name(value: &str) -> SymbolicName {
        SymbolicName::new(value).expect("test symbolic name should be valid")
    }

    fn scope_document() -> PolicyDocument {
        PolicyDocument::ScopePolicy(scope_policy_envelope())
    }

    fn scope_policy_envelope() -> ScopePolicyDocument {
        PolicyEnvelope {
            api_version: ApiVersion::V1Alpha1,
            kind: PolicyKind::ScopePolicy,
            metadata: PolicyMetadata {
                name: "scope-policy".into(),
                version: "1.0.0".into(),
            },
            scope: ScopePolicyScope {
                target: ScopeTarget::Workspace,
            },
            requirements: vec![ScopePolicyRequirement {
                selector: ScopeSelector::Source,
                constraint: ScopeConstraint::InScope,
            }],
            declarations: PolicyDeclarations::default(),
        }
    }

    fn phase_document() -> PolicyDocument {
        PolicyDocument::PhaseSeparationPolicy(PolicyEnvelope {
            api_version: ApiVersion::V1Alpha1,
            kind: PolicyKind::PhaseSeparationPolicy,
            metadata: PolicyMetadata {
                name: "phase-policy".into(),
                version: "1.0.0".into(),
            },
            scope: PhaseSeparationPolicyScope {
                lifecycle: PhaseLifecycle::BuildRuntime,
            },
            requirements: vec![PhaseSeparationRequirement {
                producer: PhaseName::Build,
                consumer: PhaseName::Sign,
                relation: PhaseRelation::Isolated,
            }],
            declarations: PolicyDeclarations::default(),
        })
    }

    fn edge_budget_document() -> PolicyDocument {
        PolicyDocument::EdgeBudgetPolicy(PolicyEnvelope {
            api_version: ApiVersion::V1Alpha1,
            kind: PolicyKind::EdgeBudgetPolicy,
            metadata: PolicyMetadata {
                name: "edge-policy".into(),
                version: "1.0.0".into(),
            },
            scope: EdgeBudgetPolicyScope {
                graph: GraphKind::Dependency,
            },
            requirements: vec![EdgeBudgetRequirement {
                source: jw_guard_policy_schema::NodeClass::Package,
                target: jw_guard_policy_schema::NodeClass::Service,
                max_edges: 4,
            }],
            declarations: PolicyDeclarations::default(),
        })
    }

    fn port_profile_document() -> PolicyDocument {
        PolicyDocument::PortProfilePolicy(PolicyEnvelope {
            api_version: ApiVersion::V1Alpha1,
            kind: PolicyKind::PortProfilePolicy,
            metadata: PolicyMetadata {
                name: "port-policy".into(),
                version: "1.0.0".into(),
            },
            scope: PortProfilePolicyScope {
                environment: PortEnvironment::Production,
            },
            requirements: vec![PortProfileRequirement {
                profile: PortProfile::ControlPlane,
                transport: TransportProtocol::Tcp,
                port: 9443,
                exposure: PortExposure::Internal,
            }],
            declarations: PolicyDeclarations::default(),
        })
    }

    fn transport_routes_document() -> PolicyDocument {
        PolicyDocument::TransportRoutesPolicy(PolicyEnvelope {
            api_version: ApiVersion::V1Alpha1,
            kind: PolicyKind::TransportRoutesPolicy,
            metadata: PolicyMetadata {
                name: "routes-policy".into(),
                version: "1.0.0".into(),
            },
            scope: TransportRoutesPolicyScope {
                topology: RouteTopology::Mesh,
            },
            requirements: vec![TransportRouteRequirement {
                from: RouteEndpoint::Runtime,
                to: RouteEndpoint::ControlPlane,
                transport: TransportProtocol::Grpc,
                action: RouteAction::Allow,
            }],
            declarations: PolicyDeclarations::default(),
        })
    }
}
