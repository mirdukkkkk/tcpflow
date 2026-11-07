use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() {
    println!("TCPFLOW version {VERSION}\n");
    println!("usage: tcpflow [options] [expression]");
    println!("\nSee SPEC.md for the options. Most of them are not implemented yet.");
}

fn run() -> Result<ExitCode, lexopt::Error> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    if let Some(arg) = parser.next()? {
        match arg {
            Short('V') | Long("version") => {
                println!("TCPFLOW {VERSION}");
                return Ok(ExitCode::SUCCESS);
            }
            Short('h') | Long("help") => {
                usage();
                return Ok(ExitCode::SUCCESS);
            }
            _ => return Err(arg.unexpected()),
        }
    }
    eprintln!("tcpflow: packet processing is not implemented yet");
    Ok(ExitCode::FAILURE)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tcpflow: {e}");
            usage();
            ExitCode::FAILURE
        }
    }
}
