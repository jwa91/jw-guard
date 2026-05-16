use std::io::Write;

use crate::report::{PathSegment, ValidationReport};

pub fn render_human_report(writer: &mut dyn Write, report: &ValidationReport) -> std::io::Result<()> {
    if report.errors.is_empty() {
        writeln!(
            writer,
            "ok: {} ({:?}) stage_reached={:?}",
            report.input.path, report.input.format, report.stage_reached
        )?;
        return Ok(());
    }

    writeln!(
        writer,
        "outcome={:?} path={} format={:?} stage_reached={:?}",
        report.outcome, report.input.path, report.input.format, report.stage_reached
    )?;
    for (index, error) in report.errors.iter().enumerate() {
        let path = format_path(&error.path);
        if let Some(source) = &error.source {
            writeln!(
                writer,
                "{}. [{}::{:?}] {} at {}:{} ({})",
                index + 1,
                stage_label(error.stage),
                error.code,
                error.message,
                source.line,
                source.column,
                path
            )?;
        } else {
            writeln!(
                writer,
                "{}. [{}::{:?}] {} ({})",
                index + 1,
                stage_label(error.stage),
                error.code,
                error.message,
                path
            )?;
        }
    }
    Ok(())
}

fn format_path(path: &[PathSegment]) -> String {
    if path.is_empty() {
        return "-".to_owned();
    }

    let mut rendered = String::new();
    for segment in path {
        match segment {
            PathSegment::Key(key) => {
                if !rendered.is_empty() {
                    rendered.push('.');
                }
                rendered.push_str(key);
            }
            PathSegment::Index(index) => {
                rendered.push('[');
                rendered.push_str(&index.to_string());
                rendered.push(']');
            }
        }
    }
    rendered
}

fn stage_label(stage: crate::report::Stage) -> &'static str {
    match stage {
        crate::report::Stage::Syntax => "syntax",
        crate::report::Stage::Wire => "wire",
        crate::report::Stage::Validation => "validation",
        crate::report::Stage::Concretise => "concretise",
    }
}
