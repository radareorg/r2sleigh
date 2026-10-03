//! Tab completion at the shell's prompt.
//!
//! What can be completed is read from the same places the shell answers
//! from: a verb from the one verb table dispatch runs ([`VERBS`]), a name
//! from the names `f` lists. Where the word under the cursor is depends only
//! on the line, so [`candidates`] is a function of the line, the cursor and
//! the names, and is tested as one.

use crate::commands::{Arguments, VERBS};
use reedline::{Span, Suggestion};
use std::sync::{Arc, Mutex};

/// One completion: the text that replaces the word, and what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub value: String,
    pub description: Option<String>,
}

/// Where the word being completed starts, and what may replace it.
///
/// The word is the one under the cursor in the statement the cursor is in
/// (statements are cut at `;`). A grep (`~`) completes nothing. After `@`,
/// or as the argument of a verb that takes an address, the word is a name.
/// Otherwise, at the start of the statement, it is a verb.
pub(crate) fn candidates(line: &str, cursor: usize, names: &[String]) -> (usize, Vec<Candidate>) {
    let cursor = cursor.min(line.len());
    let before = &line[..cursor];
    let statement_start = before.rfind(';').map_or(0, |at| at + 1);
    let statement = &before[statement_start..];
    if statement.contains('~') {
        return (cursor, Vec::new());
    }
    let word_start = statement
        .rfind(|c: char| c.is_whitespace() || c == '@')
        .map_or(0, |at| {
            at + statement[at..].chars().next().map_or(1, char::len_utf8)
        });
    let word = &statement[word_start..];
    let start = statement_start + word_start;
    let in_seek = statement[..word_start].contains('@');
    let leading = statement[..word_start].trim();
    let names_wanted = in_seek
        || (!leading.is_empty()
            && crate::commands::find(leading.split_whitespace().next().unwrap_or(""))
                .is_some_and(|verb| verb.arguments == Arguments::Address));
    if names_wanted {
        let found = names
            .iter()
            .filter(|name| name.starts_with(word))
            .map(|name| Candidate {
                value: name.clone(),
                description: None,
            })
            .collect();
        return (start, found);
    }
    if !leading.is_empty() {
        return (cursor, Vec::new());
    }
    let found = VERBS
        .iter()
        .flat_map(|verb| verb.names.iter().map(move |name| (*name, verb.summary)))
        .filter(|(name, _)| name.starts_with(word))
        .map(|(name, summary)| Candidate {
            value: name.to_owned(),
            description: Some(summary.to_owned()),
        })
        .collect();
    (start, found)
}

/// The prompt's completer: the names are the session's, refreshed by the
/// prompt before each line is read.
pub(crate) struct Completer {
    pub names: Arc<Mutex<Vec<String>>>,
}

impl reedline::Completer for Completer {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let names = self
            .names
            .lock()
            .map(|names| names.clone())
            .unwrap_or_default();
        let (start, found) = candidates(line, pos, &names);
        found
            .into_iter()
            .map(|candidate| Suggestion {
                value: candidate.value,
                description: candidate.description,
                span: Span::new(start, pos),
                append_whitespace: true,
                ..Suggestion::default()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(line: &str, names: &[&str]) -> (usize, Vec<String>) {
        let names = names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        let (start, found) = candidates(line, line.len(), &names);
        (
            start,
            found.into_iter().map(|candidate| candidate.value).collect(),
        )
    }

    #[test]
    fn a_verb_completes_from_the_table_at_the_start_of_a_statement() {
        let (start, found) = values("pd", &[]);
        assert_eq!(start, 0);
        for verb in ["pd", "pdf", "pdd", "pddj", "pdil", "pdim", "pdih", "pddo"] {
            assert!(found.iter().any(|name| name == verb), "{verb}: {found:?}");
        }
        assert!(!found.iter().any(|name| name == "px"));
        // The second statement on a line starts at its `;`.
        assert_eq!(
            values("s 0x10; af", &[]).1,
            ["afl", "aflj", "afi", "afb", "afv"]
        );
        assert_eq!(values("s 0x10; af", &[]).0, 8);
    }

    #[test]
    fn a_name_completes_after_the_seek_and_as_an_address_argument() {
        let names = ["main", "sym.main", "sym.fnv1a32", "entry0"];
        assert_eq!(
            values("pdd @ sym.f", &names),
            (6, vec!["sym.fnv1a32".to_owned()])
        );
        assert_eq!(
            values("pdd sym.m", &names),
            (4, vec!["sym.main".to_owned()])
        );
        assert_eq!(values("pd 10 @ ma", &names), (8, vec!["main".to_owned()]));
        // A count is not an address, and a grep completes nothing.
        assert!(values("pd ma", &names).1.is_empty());
        assert!(values("afl~ma", &names).1.is_empty());
    }
}
