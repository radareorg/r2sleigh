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

use crate::var::SSAVarNameKind;

/// One spelling, stored once for the life of the process.
///
/// Everything a spelling decides on its own -- which kind of location it
/// names, and the register offset it spells when it names one -- is settled
/// here rather than re-parsed at each of the hundreds of thousands of places
/// that ask.
pub struct InternedName {
    id: u32,
    text: &'static str,
    kind: SSAVarNameKind,
    register_offset: Option<u64>,
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

    /// Which kind of location this spelling names.
    pub const fn kind(&self) -> SSAVarNameKind {
        self.kind
    }

    /// The register-space offset this spelling stands for, when it spells one.
    pub const fn register_offset(&self) -> Option<u64> {
        self.register_offset
    }
}

impl PartialEq for InternedName {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for InternedName {}

impl std::hash::Hash for InternedName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
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
    let name: &'static InternedName = Box::leak(Box::new(InternedName {
        id,
        text,
        kind: SSAVarNameKind::classify(text),
        register_offset: text
            .strip_prefix("reg:")
            .and_then(|rest| u64::from_str_radix(rest, 16).ok()),
    }));
    names.insert(text, name);
    name
}

/// A spelling written into the stack, so a name the table already holds
/// costs no allocation at all.
///
/// Sixty-four bytes covers every spelling the lifter builds -- the longest is
/// a space number and a sixteen-digit offset -- and a longer one falls back to
/// the heap rather than truncating, because a truncated name would silently
/// merge two locations.
struct StackSpelling {
    buffer: [u8; 64],
    len: usize,
    spilled: Option<String>,
}

impl StackSpelling {
    const fn new() -> Self {
        Self {
            buffer: [0; 64],
            len: 0,
            spilled: None,
        }
    }

    fn push_lowercased(&mut self, text: &str) {
        if self.spilled.is_none() && self.len + text.len() <= self.buffer.len() {
            for (slot, byte) in self.buffer[self.len..].iter_mut().zip(text.bytes()) {
                *slot = byte.to_ascii_lowercase();
            }
            self.len += text.len();
            return;
        }
        let mut spilled = String::from(self.as_str());
        spilled.push_str(&text.to_ascii_lowercase());
        self.spilled = Some(spilled);
    }

    fn as_str(&self) -> &str {
        match self.spilled.as_deref() {
            Some(spilled) => spilled,
            // Every write is a `&str`, so the bytes are valid UTF-8.
            None => std::str::from_utf8(&self.buffer[..self.len]).unwrap_or_default(),
        }
    }
}

impl std::fmt::Write for StackSpelling {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if let Some(spilled) = self.spilled.as_mut() {
            spilled.push_str(text);
            return Ok(());
        }
        if self.len + text.len() <= self.buffer.len() {
            self.buffer[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
            self.len += text.len();
            return Ok(());
        }
        let mut spilled = String::with_capacity(self.len + text.len());
        spilled.push_str(self.as_str());
        spilled.push_str(text);
        self.spilled = Some(spilled);
        Ok(())
    }
}

/// The entry for a spelling given as a format, written without allocating one.
pub fn intern_fmt(spelling: std::fmt::Arguments<'_>) -> &'static InternedName {
    use std::fmt::Write;
    let mut written = StackSpelling::new();
    let _ = written.write_fmt(spelling);
    intern(written.as_str())
}

/// The entry for a spelling lowercased on the way in.
///
/// Lowercasing a byte at a time is exact here because only `A`-`Z` change and
/// those bytes never appear inside a multi-byte sequence; a name carrying
/// anything but ASCII takes the Unicode path instead.
pub fn intern_ascii_lowercase(text: &str) -> &'static InternedName {
    if !text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return intern(text);
    }
    if !text.is_ascii() {
        return intern(&text.to_lowercase());
    }
    let mut written = StackSpelling::new();
    written.push_lowercased(text);
    intern(written.as_str())
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
