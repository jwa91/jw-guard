use std::io::Write;

use crate::report::ValidationReport;

pub fn render_json_report(writer: &mut dyn Write, report: &ValidationReport) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, report)?;
    writer.write_all(b"\n")
}
