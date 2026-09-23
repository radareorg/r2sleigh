//! r2s: a radare2-compatible shell over the r2sleigh engine.

mod commands;
mod listing;
mod session;

use clap::Parser;
use std::io::{BufRead, Write};

#[derive(Parser)]
#[command(
    name = "r2s",
    about = "Engine shell with a radare2-compatible command surface"
)]
struct Cli {
    /// Binary to open
    file: String,

    /// Run these commands, separated by `;`, then exit
    #[arg(short = 'c', long)]
    command: Option<String>,

    /// Print no banner and no prompt
    #[arg(short = 'q', long)]
    quiet: bool,
}

fn main() {
    let cli = Cli::parse();
    let mut session = match session::Session::open(&cli.file) {
        Ok(session) => session,
        Err(message) => {
            eprintln!("r2s: {}", message);
            std::process::exit(1);
        }
    };

    if let Some(script) = cli.command {
        let failed = run_script(&mut session, &script);
        std::process::exit(if failed { 1 } else { 0 });
    }

    if !cli.quiet {
        let arch = session.image().arch();
        println!(
            "r2s: {} {:?} {} {}-bit, entry {:#x}",
            cli.file,
            session.image().format(),
            arch.name,
            arch.bits,
            session.addr
        );
    }

    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        if !cli.quiet {
            print!("[{:#010x}]> ", session.addr);
            let _ = std::io::stdout().flush();
        }
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("r2s: {}", error);
                break;
            }
        }
        if run_script(&mut session, &line) && line.trim() == "q" {
            break;
        }
    }
}

/// Run `;`-separated commands, reporting whether any of them failed.
fn run_script(session: &mut session::Session, script: &str) -> bool {
    let mut failed = false;
    for command in script.split(';') {
        match commands::run(session, command) {
            Ok(output) => {
                if !output.is_empty() {
                    println!("{}", output);
                }
            }
            Err(message) if message == "quit" => return true,
            Err(message) => {
                eprintln!("r2s: {}", message);
                failed = true;
            }
        }
    }
    failed
}
