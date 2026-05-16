use jw_guard_core::DeclaredModel;
use jw_guard_declare::{concretise, DeclaredSpec};

struct PipelineOutcome {
    spec_a: DeclaredSpec,
    spec_b: DeclaredSpec,
    model_a: DeclaredModel,
    model_b: DeclaredModel,
    bytes_second_pass: Vec<u8>,
    bytes_third_pass: Vec<u8>,
}

#[test]
fn full_pipeline_is_equivalent_and_deterministic_across_formats() {
    let json = run_json_pipeline(include_bytes!("../../docs/examples/declared_spec.example.json"));
    let yaml = run_yaml_pipeline(include_bytes!("../../docs/examples/declared_spec.example.yaml"));
    let toml = run_toml_pipeline(include_bytes!("../../docs/examples/declared_spec.example.toml"));

    // Invariant 1 + 2: pipeline composes and round-trip purity holds per format.
    assert_eq!(json.spec_a, json.spec_b);
    assert_eq!(yaml.spec_a, yaml.spec_b);
    assert_eq!(toml.spec_a, toml.spec_b);
    assert_eq!(json.model_a, json.model_b);
    assert_eq!(yaml.model_a, yaml.model_b);
    assert_eq!(toml.model_a, toml.model_b);
    assert_eq!(json.bytes_second_pass, json.bytes_third_pass);
    assert_eq!(yaml.bytes_second_pass, yaml.bytes_third_pass);
    assert_eq!(toml.bytes_second_pass, toml.bytes_third_pass);

    // Invariant 3: three skins produce one identical model.
    assert_eq!(json.model_a, yaml.model_a);
    assert_eq!(yaml.model_a, toml.model_a);

    // Invariant 4 + 5: deterministically derived IDs and canonical paths are identical.
    assert_eq!(json.model_a.model.id, yaml.model_a.model.id);
    assert_eq!(yaml.model_a.model.id, toml.model_a.model.id);
    assert_eq!(json.model_a.canonical_paths, yaml.model_a.canonical_paths);
    assert_eq!(yaml.model_a.canonical_paths, toml.model_a.canonical_paths);
}

fn run_json_pipeline(input: &[u8]) -> PipelineOutcome {
    let spec_a = jw_guard_adapter_json::parse_to_spec(input).expect("json parse_to_spec should succeed");
    let model_a = concretise(&spec_a).expect("json concretise should succeed");

    let wire_first = jw_guard_adapter_json::parse(input).expect("json parse should succeed");
    let bytes_second_pass = jw_guard_adapter_json::serialize(&wire_first).expect("json serialize should succeed");

    let spec_b =
        jw_guard_adapter_json::parse_to_spec(&bytes_second_pass).expect("json second parse_to_spec should succeed");
    let model_b = concretise(&spec_b).expect("json second concretise should succeed");

    let wire_second = jw_guard_adapter_json::parse(&bytes_second_pass).expect("json reparse should succeed");
    let bytes_third_pass = jw_guard_adapter_json::serialize(&wire_second).expect("json reserialize should succeed");

    PipelineOutcome {
        spec_a,
        spec_b,
        model_a,
        model_b,
        bytes_second_pass,
        bytes_third_pass,
    }
}

fn run_yaml_pipeline(input: &[u8]) -> PipelineOutcome {
    let spec_a = jw_guard_adapter_yaml::parse_to_spec(input).expect("yaml parse_to_spec should succeed");
    let model_a = concretise(&spec_a).expect("yaml concretise should succeed");

    let wire_first = jw_guard_adapter_yaml::parse(input).expect("yaml parse should succeed");
    let bytes_second_pass = jw_guard_adapter_yaml::serialize(&wire_first).expect("yaml serialize should succeed");

    let spec_b =
        jw_guard_adapter_yaml::parse_to_spec(&bytes_second_pass).expect("yaml second parse_to_spec should succeed");
    let model_b = concretise(&spec_b).expect("yaml second concretise should succeed");

    let wire_second = jw_guard_adapter_yaml::parse(&bytes_second_pass).expect("yaml reparse should succeed");
    let bytes_third_pass = jw_guard_adapter_yaml::serialize(&wire_second).expect("yaml reserialize should succeed");

    PipelineOutcome {
        spec_a,
        spec_b,
        model_a,
        model_b,
        bytes_second_pass,
        bytes_third_pass,
    }
}

fn run_toml_pipeline(input: &[u8]) -> PipelineOutcome {
    let spec_a = jw_guard_adapter_toml::parse_to_spec(input).expect("toml parse_to_spec should succeed");
    let model_a = concretise(&spec_a).expect("toml concretise should succeed");

    let wire_first = jw_guard_adapter_toml::parse(input).expect("toml parse should succeed");
    let bytes_second_pass = jw_guard_adapter_toml::serialize(&wire_first).expect("toml serialize should succeed");

    let spec_b =
        jw_guard_adapter_toml::parse_to_spec(&bytes_second_pass).expect("toml second parse_to_spec should succeed");
    let model_b = concretise(&spec_b).expect("toml second concretise should succeed");

    let wire_second = jw_guard_adapter_toml::parse(&bytes_second_pass).expect("toml reparse should succeed");
    let bytes_third_pass = jw_guard_adapter_toml::serialize(&wire_second).expect("toml reserialize should succeed");

    PipelineOutcome {
        spec_a,
        spec_b,
        model_a,
        model_b,
        bytes_second_pass,
        bytes_third_pass,
    }
}
