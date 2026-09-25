//! r2s: a radare2-compatible shell over the r2sleigh engine.

mod commands;
mod function;
mod grep;
mod line;
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

    /// Run these commands, separated by `;` or by lines, then exit
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

    let mut reader = line::Reader::default();
    if let Some(script) = cli.command {
        let failed = run_script(&mut session, &mut reader, &script);
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
        if run_script(&mut session, &mut reader, &line) && line.trim() == "q" {
            break;
        }
    }
}

/// Run a script line by line, reporting whether any statement failed or
/// quit.
///
/// Every line is cut and every statement's grep parsed before the first one
/// runs; a statement that was refused runs nothing, and the rest still run. A
/// quit ends its line: radare2 goes on with the next (cmd.c:6997-7003). After
/// a line that failed or quit, the first statement that fails ends the script
/// ([`line::UNSETTLED`]).
fn run_script(session: &mut session::Session, reader: &mut line::Reader, script: &str) -> bool {
    let lines = reader.script(script);
    let total = lines.len();
    let mut run = Run::default();
    for (index, statements) in lines.into_iter().enumerate() {
        if !run.line(session, statements, index + 1 == total) {
            break;
        }
    }
    run.failed || run.quit
}

/// What running a script has come to so far.
#[derive(Default)]
struct Run {
    failed: bool,
    quit: bool,
    /// A line failed or quit, after which radare2 may run the rest of the
    /// script as one command.
    unsettled: bool,
}

impl Run {
    /// Run one line's statements, and say whether the script goes on.
    fn line(&mut self, session: &mut session::Session, statements: line::Line, last: bool) -> bool {
        let unsettled = self.unsettled;
        let count = statements.len();
        for (at, statement) in statements.into_iter().enumerate() {
            let message = match statement.and_then(|statement| commands::run(session, &statement)) {
                Ok(output) => {
                    print!("{output}");
                    continue;
                }
                Err(message) => message,
            };
            self.unsettled = true;
            if message == "quit" {
                self.quit = true;
                return true;
            }
            eprintln!("r2s: {}", message);
            self.failed = true;
            if unsettled && !(last && at + 1 == count) {
                eprintln!("r2s: {}", line::UNSETTLED);
                return false;
            }
        }
        true
    }
}
