use std::fs;
use std::path::PathBuf;

fn main() {
    let schema = jw_guard_wire::declared_spec_schema_value();
    let serialized = serde_json::to_string_pretty(&schema).expect("schema should serialize");

    let mut output = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    output.pop();
    output.push("schemas");
    output.push("declared-spec-wire.schema.json");

    fs::create_dir_all(
        output
            .parent()
            .expect("schema output path should always have a parent"),
    )
    .expect("schema directory should be creatable");
    fs::write(&output, format!("{serialized}\n")).expect("schema file should be writable");
}
