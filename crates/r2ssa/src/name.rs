//! Interned variable names.
//!
//! A variable's name is its display spelling, and the same few thousand
//! spellings are repeated across every operation of every function: a
//! five-hundred-block function holds on the order of a million variables whose
//! names are copies of a few hundred register and temporary spellings. Boxing
//! one string per occurrence made every clone an allocation, every equality a
//! `memcmp` and every hash a walk over the bytes.
//!
//! Interning replaces all three. A spelling is stored once, and a variable
//! carries a pointer to it: cloning copies eight bytes, equality is a pointer
//! comparison, and hashing is the interned identifier. Ordering still compares
//! the text, so every map keyed by a variable iterates exactly as before.
//!
//! Entries are never freed. The set is bounded by the distinct spellings a
//! program contains, which is what a decompiler holds anyway, and a name that
//! outlives the function it came from is what lets a variable be `'static`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// One spelling, stored once for the life of the process.
pub struct InternedName {
    id: u32,
    text: &'static str,
}

impl InternedName {
    /// The spelling itself.
    pub const fn text(&self) -> &'static str {
        self.text
    }

    /// A dense identifier, unique to this spelling within the process.
    pub const fn id(&self) -> u32 {
        self.id
    }
}

impl std::fmt::Debug for InternedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.text, f)
    }
}

static NAMES: LazyLock<Mutex<HashMap<&'static str, &'static InternedName>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The single entry for a spelling, creating it the first time it is seen.
pub fn intern(text: &str) -> &'static InternedName {
    let mut names = NAMES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(found) = names.get(text) {
        return found;
    }
    let text: &'static str = Box::leak(text.to_owned().into_boxed_str());
    let id = u32::try_from(names.len()).unwrap_or(u32::MAX);
    let name: &'static InternedName = Box::leak(Box::new(InternedName { id, text }));
    names.insert(text, name);
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_spelling_is_stored_once() {
        let first = intern("interning-test-rax");
        let second = intern(&String::from("interning-test-rax"));
        assert!(std::ptr::eq(first, second));
        assert_eq!(first.text(), "interning-test-rax");
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn different_spellings_are_different_entries() {
        let first = intern("interning-test-a");
        let second = intern("interning-test-b");
        assert!(!std::ptr::eq(first, second));
        assert_ne!(first.id(), second.id());
    }
}
