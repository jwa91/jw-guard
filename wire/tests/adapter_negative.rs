use serde_json::Value;

fn json_fixture() -> Value {
    serde_json::from_slice(include_bytes!("../../docs/examples/declared_spec.example.json"))
        .expect("json fixture must parse")
}

#[test]
fn json_rejects_duplicate_keys_and_trailing_data() {
    let duplicate_root = br#"{"schema_version":"v1","schema_version":"v2"}"#;
    let trailing_data = br#"{"schema_version":"v1"} trailing"#;

    assert!(matches!(
        jw_guard_adapter_json::parse(duplicate_root),
        Err(jw_guard_adapter_json::AdapterError::Syntax(_))
    ));
    assert!(matches!(
        jw_guard_adapter_json::parse(trailing_data),
        Err(jw_guard_adapter_json::AdapterError::Syntax(_))
    ));
}

#[test]
fn unknown_fields_are_rejected_across_formats() {
    let mut json = json_fixture();
    let Value::Object(ref mut map) = json else {
        panic!("fixture root must be an object");
    };
    map.insert("unknown_field".to_owned(), Value::Bool(true));
    let json_bytes = serde_json::to_vec(&json).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&json_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));

    let mut yaml = include_str!("../../docs/examples/declared_spec.example.yaml").to_owned();
    yaml.push_str("\nunknown_field: true\n");
    assert!(matches!(
        jw_guard_adapter_yaml::parse(yaml.as_bytes()),
        Err(jw_guard_adapter_yaml::AdapterError::Wire(_))
    ));

    let mut toml = include_str!("../../docs/examples/declared_spec.example.toml").to_owned();
    toml.push_str("\nunknown_field = true\n");
    assert!(matches!(
        jw_guard_adapter_toml::parse(toml.as_bytes()),
        Err(jw_guard_adapter_toml::AdapterError::Wire(_))
    ));
}

#[test]
fn invalid_union_kind_is_wire_shape_error() {
    let mut json = json_fixture();
    let Value::Object(ref mut root) = json else {
        panic!("fixture root must be an object");
    };
    let Value::Array(scopes) = root
        .get_mut("scopes")
        .expect("scopes should exist")
    else {
        panic!("scopes should be an array");
    };
    let Value::Object(first_scope) = scopes.first_mut().expect("scope should exist") else {
        panic!("scope should be object");
    };
    first_scope.insert(
        "predicate".to_owned(),
        serde_json::json!({
            "kind": "not_a_real_kind",
            "name": "frontend"
        }),
    );

    let json_bytes = serde_json::to_vec(&json).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&json_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));
}

#[test]
fn parse_to_spec_reports_wire_error_for_invalid_symbolic_name() {
    let mut json = json_fixture();
    let Value::Object(ref mut root) = json else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    model.insert("name".to_owned(), Value::String("InvalidName".to_owned()));
    let json_bytes = serde_json::to_vec(&json).expect("json should serialize");

    assert!(jw_guard_adapter_json::parse(&json_bytes).is_ok());
    assert!(matches!(
        jw_guard_adapter_json::parse_to_spec(&json_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(jw_guard_adapter_json::WireError::Declare(_)))
    ));
}

#[test]
fn yaml_forbidden_features_are_syntax_errors() {
    let cases: [&[u8]; 5] = [
        b"schema_version: v1\nroot: &anchor value\n",
        b"schema_version: v1\nroot: *alias\n",
        b"schema_version: v1\nroot: !!str tagged\n",
        b"schema_version: v1\nroot:\n  <<: {a: 1}\n",
        b"---\nschema_version: v1\n---\nschema_version: v1\n",
    ];

    for input in cases {
        assert!(matches!(
            jw_guard_adapter_yaml::parse(input),
            Err(jw_guard_adapter_yaml::AdapterError::Syntax(_))
        ));
    }
}

#[test]
fn nested_unknown_field_missing_required_and_type_mismatches_are_wire_errors() {
    let mut nested_unknown = json_fixture();
    let Value::Object(ref mut root) = nested_unknown else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    model.insert("unknown_inner".to_owned(), Value::Bool(true));
    let nested_unknown_bytes = serde_json::to_vec(&nested_unknown).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&nested_unknown_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));

    let mut missing_required = json_fixture();
    let Value::Object(ref mut root) = missing_required else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    model.remove("declared_by");
    let missing_required_bytes = serde_json::to_vec(&missing_required).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&missing_required_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));

    let mut wrong_type = json_fixture();
    let Value::Object(ref mut root) = wrong_type else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    let Value::Object(version) = model.get_mut("version").expect("version should exist") else {
        panic!("version should be object");
    };
    version.insert("major".to_owned(), Value::String("1".to_owned()));
    let wrong_type_bytes = serde_json::to_vec(&wrong_type).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&wrong_type_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));
}

#[test]
fn integer_range_and_null_in_non_explicit_option_are_wire_errors() {
    let mut out_of_range = json_fixture();
    let Value::Object(ref mut root) = out_of_range else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    let Value::Object(version) = model.get_mut("version").expect("version should exist") else {
        panic!("version should be object");
    };
    version.insert("major".to_owned(), Value::Number(70000u64.into()));
    let out_of_range_bytes = serde_json::to_vec(&out_of_range).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&out_of_range_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));

    let mut null_non_option = json_fixture();
    let Value::Object(ref mut root) = null_non_option else {
        panic!("fixture root must be an object");
    };
    let Value::Object(model) = root.get_mut("model").expect("model should exist") else {
        panic!("model should be object");
    };
    model.insert("declared_by".to_owned(), Value::Null);
    let null_non_option_bytes = serde_json::to_vec(&null_non_option).expect("json should serialize");
    assert!(matches!(
        jw_guard_adapter_json::parse(&null_non_option_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
    ));
}

#[test]
fn parse_succeeds_but_parse_to_spec_fails_for_multiple_symbolic_name_fields() {
    let mut json = json_fixture();
    let Value::Object(ref mut root) = json else {
        panic!("fixture root must be an object");
    };
    let Value::Array(actors) = root.get_mut("actors").expect("actors should exist") else {
        panic!("actors should be array");
    };
    let Value::Object(actor0) = actors.first_mut().expect("actor should exist") else {
        panic!("actor should be object");
    };
    actor0.insert("name".to_owned(), Value::String("InvalidActor".to_owned()));

    let Value::Array(policies) = root.get_mut("policies").expect("policies should exist") else {
        panic!("policies should be array");
    };
    let Value::Object(policy0) = policies.first_mut().expect("policy should exist") else {
        panic!("policy should be object");
    };
    policy0.insert("scope".to_owned(), Value::String("InvalidScope".to_owned()));

    let json_bytes = serde_json::to_vec(&json).expect("json should serialize");
    assert!(jw_guard_adapter_json::parse(&json_bytes).is_ok());
    assert!(matches!(
        jw_guard_adapter_json::parse_to_spec(&json_bytes),
        Err(jw_guard_adapter_json::AdapterError::Wire(jw_guard_adapter_json::WireError::Declare(_)))
    ));
}
