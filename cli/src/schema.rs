use std::io::Write;

pub fn emit_schema(writer: &mut dyn Write) -> std::io::Result<()> {
    let value = jw_guard_wire::declared_spec_schema_value();
    serde_json::to_writer_pretty(&mut *writer, &value)?;
    writer.write_all(b"\n")
}
