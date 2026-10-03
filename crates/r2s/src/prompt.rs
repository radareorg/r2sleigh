//! The shell's prompt on a terminal: line editing, history and its search.
//!
//! Only a terminal gets this. A pipe, `-c` and `-q` read lines as they come
//! and print no prompt, so a script's output is the same byte for byte
//! whoever runs it.

use crate::line::Reader;
use crate::session::Session;
use reedline::{
    ColumnarMenu, Emacs, FileBackedHistory, KeyCode, KeyModifiers, MenuBuilder, Prompt,
    PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline, ReedlineEvent,
    ReedlineMenu, Signal, default_emacs_keybindings,
};
use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// How many lines the history keeps.
const HISTORY: usize = 1000;

/// Where the history is kept: `~/.r2s_history`, or nowhere without a home.
fn history_file(home: Option<&OsStr>) -> Option<PathBuf> {
    home.filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(".r2s_history"))
}

/// The name of the menu Tab opens.
const COMPLETIONS: &str = "completions";

/// The line editor, its history read from the file where there is one and
/// held in memory otherwise, and Tab completing verbs and names.
fn editor(names: Arc<Mutex<Vec<String>>>) -> Reedline {
    let file = history_file(std::env::var_os("HOME").as_deref());
    let history = match file {
        Some(file) => FileBackedHistory::with_file(HISTORY, file.clone()).map_err(|error| {
            eprintln!(
                "r2s: history {}: {error}; kept for this session only",
                file.display()
            );
        }),
        None => Err(()),
    }
    .or_else(|()| FileBackedHistory::new(HISTORY).map_err(|_| ()));
    let mut keys = default_emacs_keybindings();
    keys.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu(COMPLETIONS.to_owned()),
            ReedlineEvent::MenuNext,
        ]),
    );
    let editor = Reedline::create()
        .with_completer(Box::new(crate::complete::Completer { names }))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(
            ColumnarMenu::default().with_name(COMPLETIONS),
        )))
        .with_edit_mode(Box::new(Emacs::new(keys)));
    match history {
        Ok(history) => editor.with_history(Box::new(history)),
        Err(()) => editor,
    }
}

/// radare2's prompt: the seek, in brackets.
struct Seek(u64);

impl Prompt for Seek {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned(format!("[{:#010x}]", self.0))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("... ")
    }

    fn render_prompt_history_search_indicator(&self, search: PromptHistorySearch) -> Cow<'_, str> {
        let failing = match search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };
        Cow::Owned(format!("({failing}reverse-i-search: {}) ", search.term))
    }
}

/// How the line editor stopped.
pub(crate) enum Ended {
    /// A quit, or `Ctrl-D`: the shell is done.
    Left,
    /// The editor could not drive this terminal -- one that never answers a
    /// cursor-position query, for instance. The session goes on, read the
    /// plain way.
    EditorFailed,
}

/// Read lines at the terminal and run each, until one quits, the user leaves
/// with `Ctrl-D`, or the editor cannot drive the terminal.
pub(crate) fn interactive(session: &mut Session, reader: &mut Reader) -> Ended {
    let names = Arc::new(Mutex::new(Vec::new()));
    let mut editor = editor(Arc::clone(&names));
    loop {
        // The names `f` lists, which a command can have added to. The table
        // is complete once there is a decoder to name the linkage stubs
        // with, as `f` knows; without one there is nothing to offer.
        if session.program.ensure_current().is_ok()
            && let Ok(mut held) = names.lock()
        {
            *held = session
                .program
                .names()
                .iter()
                .map(|(_, name)| name.spelled().to_string())
                .collect();
        }
        match editor.read_line(&Seek(session.addr)) {
            Ok(Signal::Success(line)) => {
                // Whichever spelling quit, and wherever on the line it stood.
                if crate::run_script(session, reader, &line).quit {
                    return Ended::Left;
                }
            }
            // A line given up, as a shell gives it up.
            Ok(Signal::CtrlC) => {}
            Ok(Signal::CtrlD) => return Ended::Left,
            Err(error) => {
                eprintln!("r2s: line editing is unavailable here ({error}); reading lines plainly");
                return Ended::EditorFailed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_history_is_kept_in_home_and_nowhere_without_one() {
        assert_eq!(
            history_file(Some(OsStr::new("/home/r"))),
            Some(PathBuf::from("/home/r/.r2s_history"))
        );
        assert_eq!(history_file(Some(OsStr::new(""))), None);
        assert_eq!(history_file(None), None);
    }
}
