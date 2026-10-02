//! The visual mode of r2s.
//!
//! radare2's visual mode is a set of panes over one cursor: disassembly,
//! decompiled C, hex, lists of what the binary holds, and a command line that
//! runs anything the shell can. This crate is that, drawn with ratatui.
//!
//! It owns no fact about the program. Everything it shows comes through
//! [`Host`], which the shell implements with the same spellers its commands
//! use, so a line in the disassembly pane is the line `pd` prints and a pane
//! never disagrees with the command line beneath it. That also keeps this
//! crate free of the engine: it depends on nothing but the terminal.

mod app;
mod host;
mod view;

pub use app::{App, View};
pub use host::{DecompiledLine, Entry, Host, ListKind, ListedLine};

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// Run the visual mode on the terminal until the user leaves it.
///
/// The terminal is restored on every way out, an error included: a shell that
/// returns to its prompt with raw mode still on is unusable.
pub fn run(host: &mut dyn Host) -> std::io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error);
    }
    let result = (|| {
        let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
        let mut app = App::new(host);
        loop {
            terminal.draw(|frame| app.draw(frame, host))?;
            if let Event::Key(key) = event::read()?
                && !app.handle_key(host, key)
            {
                return Ok(());
            }
        }
    })();
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    result
}
