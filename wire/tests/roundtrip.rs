use jw_guard_declare::{
    ActorSpec, BoundarySpec, DeclaredSpec, EdgeSpec, ModelSpec, PolicySpec, ReferentSpec, RequirementSpec,
    RequirementValueSpec, ScopePredicateSpec, ScopeSpec, SymbolicName, VersionSpec,
};
use jw_guard_core::{Direction, RequirementOperator};

fn expected_spec() -> DeclaredSpec {
    fn name(value: &str) -> SymbolicName {
        SymbolicName::new(value).expect("test name should be valid")
    }

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
fn json_roundtrip_is_byte_stable_and_structurally_equal() {
    let input = include_bytes!("../../docs/examples/declared_spec.example.json");
    let wire = jw_guard_adapter_json::parse(input).expect("json parse should succeed");
    let first_bytes = jw_guard_adapter_json::serialize(&wire).expect("json serialize should succeed");
    let wire_second = jw_guard_adapter_json::parse(&first_bytes).expect("json parse should succeed");
    let second_bytes = jw_guard_adapter_json::serialize(&wire_second).expect("json serialize should succeed");
    assert_eq!(first_bytes, second_bytes);

    let spec = jw_guard_adapter_json::parse_to_spec(&first_bytes).expect("json parse_to_spec should succeed");
    assert_eq!(spec, expected_spec());
}

#[test]
fn yaml_roundtrip_is_byte_stable_and_structurally_equal() {
    let input = include_bytes!("../../docs/examples/declared_spec.example.yaml");
    let wire = jw_guard_adapter_yaml::parse(input).expect("yaml parse should succeed");
    let first_bytes = jw_guard_adapter_yaml::serialize(&wire).expect("yaml serialize should succeed");
    let wire_second = jw_guard_adapter_yaml::parse(&first_bytes).expect("yaml parse should succeed");
    let second_bytes = jw_guard_adapter_yaml::serialize(&wire_second).expect("yaml serialize should succeed");
    assert_eq!(first_bytes, second_bytes);

    let spec = jw_guard_adapter_yaml::parse_to_spec(&first_bytes).expect("yaml parse_to_spec should succeed");
    assert_eq!(spec, expected_spec());
}

#[test]
fn toml_roundtrip_is_byte_stable_and_structurally_equal() {
    let input = include_bytes!("../../docs/examples/declared_spec.example.toml");
    let wire = jw_guard_adapter_toml::parse(input).expect("toml parse should succeed");
    let first_bytes = jw_guard_adapter_toml::serialize(&wire).expect("toml serialize should succeed");
    let wire_second = jw_guard_adapter_toml::parse(&first_bytes).expect("toml parse should succeed");
    let second_bytes = jw_guard_adapter_toml::serialize(&wire_second).expect("toml serialize should succeed");
    assert_eq!(first_bytes, second_bytes);

    let spec = jw_guard_adapter_toml::parse_to_spec(&first_bytes).expect("toml parse_to_spec should succeed");
    assert_eq!(spec, expected_spec());
}
