use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "jw-guard",
    version,
    about = "Security policy type system for supply-chain hardening."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a future policy document.
    Check,
    /// Scan the current machine with future adapters.
    Scan,
    /// Produce a future report.
    Report,
    /// Print the CLI version.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("jw-guard {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Check | Command::Scan | Command::Report => {
            eprintln!("this command is reserved for the adapter/enforcement layer");
            ExitCode::from(2)
        }
    }
}
