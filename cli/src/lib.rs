#![forbid(unsafe_code)]

mod error_map;
mod output_human;
mod output_json;
mod report;
mod schema;
mod validate;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::output_human::render_human_report;
use crate::output_json::render_json_report;
use crate::report::{OutputFormat, StageStop};
use crate::schema::emit_schema;
use crate::validate::validate_file;

#[derive(Debug, Parser)]
#[command(name = "jw-guard")]
#[command(about = "jw-guard contract-first diagnostics CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Validate {
        path: PathBuf,
        #[arg(long = "format-override", value_enum)]
        format_override: Option<InputFormatArg>,
        #[arg(long = "stage", value_enum, default_value_t = StageArg::Concretise)]
        stage: StageArg,
        #[arg(long = "output", alias = "format", value_enum)]
        output: Option<OutputArg>,
    },
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
enum SchemaCommand {
    Emit,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StageArg {
    Parse,
    Wire,
    Validate,
    Concretise,
}

impl From<StageArg> for StageStop {
    fn from(value: StageArg) -> Self {
        match value {
            StageArg::Parse => StageStop::Parse,
            StageArg::Wire => StageStop::Wire,
            StageArg::Validate => StageStop::Validate,
            StageArg::Concretise => StageStop::Concretise,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputArg {
    Human,
    Json,
}

impl From<OutputArg> for OutputFormat {
    fn from(value: OutputArg) -> Self {
        match value {
            OutputArg::Human => OutputFormat::Human,
            OutputArg::Json => OutputFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormatArg {
    Json,
    Yaml,
    Toml,
}

impl From<InputFormatArg> for crate::report::InputFormat {
    fn from(value: InputFormatArg) -> Self {
        match value {
            InputFormatArg::Json => crate::report::InputFormat::Json,
            InputFormatArg::Yaml => crate::report::InputFormat::Yaml,
            InputFormatArg::Toml => crate::report::InputFormat::Toml,
        }
    }
}

pub fn run_from_env() -> i32 {
    let args = std::env::args_os();
    run(args, std::io::stdout().is_terminal(), &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run<I>(args: I, stdout_is_tty: bool, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = OsString>,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            return 2;
        }
    };

    match cli.command {
        Command::Validate {
            path,
            format_override,
            stage,
            output,
        } => {
            let output_mode = output.map(OutputFormat::from).unwrap_or_else(|| {
                if stdout_is_tty {
                    OutputFormat::Human
                } else {
                    OutputFormat::Json
                }
            });

            let result = validate_file(&path, format_override.map(Into::into), stage.into());
            match result {
                Ok(report) => {
                    if output_mode == OutputFormat::Json {
                        let _ = render_json_report(stdout, &report);
                    } else {
                        let _ = render_human_report(stderr, &report);
                    }

                    if report.outcome.is_ok() { 0 } else { 1 }
                }
                Err(error) => {
                    let _ = writeln!(stderr, "{error}");
                    if error.is_io() { 3 } else { 1 }
                }
            }
        }
        Command::Schema {
            command: SchemaCommand::Emit,
        } => match emit_schema(stdout) {
            Ok(()) => 0,
            Err(error) => {
                let _ = writeln!(stderr, "{error}");
                1
            }
        },
    }
}
