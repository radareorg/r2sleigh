//! The name a container gives an address (D460): a hint for printing and for a table keyed by C
//! identifier, never proof of what the code does (AGENTS.md, Non-Negotiable 6).

use std::fmt;

/// A symbol's name. It compares only with another name: no `PartialEq<str>`, `Deref`, `AsRef<str>`
/// or `Borrow<str>`, and `text` is read only where the `name_decides_fact` Dylint is allowed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolName(Box<str>);

impl SymbolName {
    pub fn new(text: impl Into<Box<str>>) -> Self {
        Self(text.into())
    }

    /// The text, for printing, an output contract or a table lookup by C identifier.
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
