use std::fs;
use std::path::PathBuf;

#[test]
fn declared_spec_schema_is_committed_and_current() {
    let mut schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    schema_path.pop();
    schema_path.push("schemas");
    schema_path.push("declared-spec-wire.schema.json");

    let committed = fs::read_to_string(&schema_path)
        .unwrap_or_else(|error| panic!("failed to read committed schema at {:?}: {error}", schema_path));

    let generated = serde_json::to_string_pretty(&jw_guard_wire::declared_spec_schema_value())
        .expect("generated schema should serialize");
    let generated = format!("{generated}\n");

    assert_eq!(
        committed, generated,
        "schema drift detected. Regenerate with `cargo run -p jw-guard-wire --bin export_schema`"
    );
}
