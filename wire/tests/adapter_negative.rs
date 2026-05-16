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
        Err(jw_guard_adapter_json::AdapterError::Syntax(_))
    ));

    let mut yaml = include_str!("../../docs/examples/declared_spec.example.yaml").to_owned();
    yaml.push_str("\nunknown_field: true\n");
    assert!(matches!(
        jw_guard_adapter_yaml::parse(yaml.as_bytes()),
        Err(jw_guard_adapter_yaml::AdapterError::Syntax(_))
    ));

    let mut toml = include_str!("../../docs/examples/declared_spec.example.toml").to_owned();
    toml.push_str("\nunknown_field = true\n");
    assert!(matches!(
        jw_guard_adapter_toml::parse(toml.as_bytes()),
        Err(jw_guard_adapter_toml::AdapterError::Syntax(_))
    ));
}

#[test]
fn invalid_union_kind_is_syntax_error() {
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
        Err(jw_guard_adapter_json::AdapterError::Syntax(_))
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
        Err(jw_guard_adapter_json::AdapterError::Wire(_))
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
