//! Reading the workspace's source the way the invariants need it: by crate
//! and by item, never by file and offset.
//!
//! A [`Source`] is text with two masks of the same length laid over it. In
//! `code` every comment, string and character literal is blanked; in `words`
//! only comments are. Finding a pattern is a plain substring search of the
//! mask it belongs to, and because the masks keep every offset, what is found
//! is cut from the original text. A brace inside a string or a name inside a
//! comment is therefore never mistaken for code, and a crate of a hundred
//! thousand lines is masked once rather than rescanned for every pattern.

use std::ops::Range;
use std::path::{Path, PathBuf};

/// The repository root: this crate lives at `tools/dylints/r2sleigh_lints`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Text and its two masks.
pub struct Source {
    raw: String,
    code: String,
    words: String,
}

/// A range of a [`Source`]: an item, a signature, a whole crate.
#[derive(Clone, Copy)]
pub struct View<'a> {
    raw: &'a str,
    code: &'a str,
    words: &'a str,
}

impl Source {
    pub fn new(raw: String) -> Self {
        let (code, words) = masks(&raw);
        Self { raw, code, words }
    }

    pub fn view(&self) -> View<'_> {
        View {
            raw: &self.raw,
            code: &self.code,
            words: &self.words,
        }
    }
}

/// A crate's production source: every non-test file under `relative` (a
/// `src` directory), each with what `#[cfg(test)]` guards removed, joined in
/// path order.
pub fn production(relative: &str) -> Source {
    let mut text = String::new();
    for path in rust_files(relative) {
        if is_test_file(&path) {
            continue;
        }
        let file = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        text.push_str(&format!("\n// ---- {}\n", path.display()));
        text.push_str(&strip_cfg_test(&Source::new(file)));
    }
    Source::new(text)
}

/// One file, read whole.
pub fn file(relative: &str) -> Source {
    let path = workspace_root().join(relative);
    Source::new(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
}

impl<'a> View<'a> {
    fn slice(self, range: Range<usize>) -> Self {
        Self {
            raw: &self.raw[range.clone()],
            code: &self.code[range.clone()],
            words: &self.words[range],
        }
    }

    pub fn text(self) -> &'a str {
        self.raw
    }

    /// Where `needle` first occurs as code.
    pub fn find(self, needle: &str) -> Option<usize> {
        self.code.find(needle)
    }

    /// Whether `needle` occurs as code.
    pub fn contains(self, needle: &str) -> bool {
        self.code.contains(needle)
    }

    /// Every line where `needle` occurs as code.
    pub fn lines_with(self, needle: &str) -> Vec<String> {
        self.lines_where(self.code, needle)
    }

    /// Every line where `needle` occurs as code or inside a string: a text a
    /// renderer might print is found as surely as a name it might call.
    pub fn lines_with_text(self, needle: &str) -> Vec<String> {
        self.lines_where(self.words, needle)
    }

    fn lines_where(self, mask: &str, needle: &str) -> Vec<String> {
        mask.match_indices(needle)
            .map(|(at, _)| {
                let start = self.raw[..at].rfind('\n').map_or(0, |newline| newline + 1);
                let end = self.raw[at..]
                    .find('\n')
                    .map_or(self.raw.len(), |end| at + end);
                self.raw[start..end].trim().to_string()
            })
            .collect()
    }

    /// Every item whose declaration begins with `header`, each through its
    /// closing brace (or `;`).
    pub fn items(self, header: &str) -> Vec<View<'a>> {
        self.code
            .match_indices(header)
            .map(|(at, _)| {
                let end = item_end(&self.code[at..], false).unwrap_or(self.code.len() - at);
                self.slice(at..at + end)
            })
            .collect()
    }

    /// The one item whose declaration begins with `header`.
    pub fn item(self, header: &str) -> View<'a> {
        let found = self.items(header);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one item declared as {header:?}, found {}; if it was renamed, \
             restate the invariant against its new name",
            found.len()
        );
        found[0]
    }

    /// The declaration of an item: everything before its body.
    pub fn signature(self) -> View<'a> {
        let end = self.code.find('{').unwrap_or(self.code.len());
        self.slice(0..end)
    }

    /// What a function takes: its signature up to the return type.
    pub fn parameters(self) -> View<'a> {
        let signature = self.signature();
        let end = signature.code.find("->").unwrap_or(signature.code.len());
        signature.slice(0..end)
    }

    /// The field names a struct item makes visible outside its crate.
    pub fn public_fields(self) -> Vec<String> {
        let Some(open) = self.code.find('{') else {
            return Vec::new();
        };
        self.code[open + 1..]
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix("pub "))
            .filter_map(|rest| rest.split(':').next())
            .map(|name| name.trim().to_string())
            .collect()
    }

    /// The attribute lines directly above the item at `at`.
    pub fn attributes_above(self, at: usize) -> Vec<String> {
        self.raw[..at]
            .trim_end()
            .lines()
            .rev()
            .map(str::trim)
            .take_while(|line| line.starts_with("#[") || line.starts_with("///"))
            .map(str::to_string)
            .collect()
    }
}

impl std::fmt::Display for View<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.raw)
    }
}

/// Every `.rs` file under `relative`, in path order.
fn rust_files(relative: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let base = workspace_root().join(relative);
    assert!(base.is_dir(), "{} is not a directory", base.display());
    let mut files = Vec::new();
    walk(&base, &mut files);
    files.sort();
    files
}

/// Whether a file is compiled only for tests: under a `tests/` directory, a
/// `tests.rs` module, or a `*_tests.rs` sibling.
fn is_test_file(path: &Path) -> bool {
    path.components().any(|part| part.as_os_str() == "tests")
        || path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem == "tests" || stem.ends_with("_tests"))
}

/// `source` without what `#[cfg(test)]` guards: an item through its body or
/// `;`, or a field, argument or statement through its `,` or `;`.
pub fn strip_cfg_test(source: &Source) -> String {
    const MARKER: &str = "#[cfg(test)]";
    let mut out = String::with_capacity(source.raw.len());
    let mut copied = 0usize;
    let mut search = 0usize;
    while let Some(found) = source.code[search..].find(MARKER) {
        let at = search + found;
        let guarded = at + MARKER.len();
        let end = guarded_end(&source.code[guarded..]).unwrap_or(source.code.len() - guarded);
        out.push_str(&source.raw[copied..at]);
        copied = guarded + end;
        search = copied;
    }
    out.push_str(&source.raw[copied..]);
    out
}

/// Where what an attribute guards ends, read from the code mask.
fn guarded_end(code: &str) -> Option<usize> {
    item_end(code, !guards_an_item(code))
}

/// Whether an attribute guards an item (a `fn`, `mod`, `impl`, ...) rather
/// than a field, argument or statement.
fn guards_an_item(code: &str) -> bool {
    let mut text = code.trim_start();
    while text.starts_with("#[") {
        text = text[attribute_len(text)..].trim_start();
    }
    if let Some(rest) = text.strip_prefix("pub") {
        text = rest.trim_start();
        if text.starts_with('(') {
            text = &text[text.find(')').map_or(text.len(), |close| close + 1)..];
        }
        text = text.trim_start();
    }
    let word = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '!'))
        .next()
        .unwrap_or_default();
    matches!(
        word,
        "mod"
            | "fn"
            | "impl"
            | "use"
            | "struct"
            | "enum"
            | "union"
            | "const"
            | "static"
            | "type"
            | "trait"
            | "unsafe"
            | "extern"
            | "async"
            | "macro_rules!"
    )
}

/// The length of the `#[...]` attribute at the start of `code`.
fn attribute_len(code: &str) -> usize {
    let mut depth = 0usize;
    for (index, byte) in code.bytes().enumerate().skip(1) {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
    }
    code.len()
}

/// Where the item, field or statement at the start of `code` ends: just after
/// the brace that closes its first body, or after the `;` (or, for a field or
/// statement, the `,`) that ends it at depth zero. One that runs into the
/// delimiter closing its enclosing scope ends just before it.
fn item_end(code: &str, comma_ends: bool) -> Option<usize> {
    let (mut braces, mut parens, mut brackets) = (0usize, 0usize, 0usize);
    for (index, byte) in code.bytes().enumerate() {
        let flat = braces == 0 && parens == 0 && brackets == 0;
        match byte {
            b'(' => parens += 1,
            b')' if parens == 0 => return Some(index),
            b')' => parens -= 1,
            b'[' => brackets += 1,
            b']' if brackets == 0 => return Some(index),
            b']' => brackets -= 1,
            b'{' => braces += 1,
            b'}' if braces == 0 => return Some(index),
            b'}' => {
                braces -= 1;
                if braces == 0 && parens == 0 && brackets == 0 && !comma_ends {
                    return Some(index + 1);
                }
            }
            b';' if flat => return Some(index + 1),
            b',' if comma_ends && flat => return Some(index + 1),
            _ => {}
        }
    }
    None
}

/// The two masks of `raw`: code only, and code with its strings.
fn masks(raw: &str) -> (String, String) {
    let mut code = Vec::with_capacity(raw.len());
    let mut words = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let blank = |span: &[u8], out: &mut Vec<u8>| {
        out.extend(
            span.iter()
                .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' }),
        );
    };
    let mut index = 0usize;
    while index < bytes.len() {
        match trivia_len(&raw[index..]) {
            Some((len, is_comment)) => {
                let span = &bytes[index..index + len];
                blank(span, &mut code);
                if is_comment {
                    blank(span, &mut words);
                } else {
                    words.extend_from_slice(span);
                }
                index += len;
            }
            None => {
                let width = raw[index..].chars().next().map_or(1, char::len_utf8);
                code.extend_from_slice(&bytes[index..index + width]);
                words.extend_from_slice(&bytes[index..index + width]);
                index += width;
            }
        }
    }
    (
        String::from_utf8(code).expect("masking keeps UTF-8"),
        String::from_utf8(words).expect("masking keeps UTF-8"),
    )
}

/// The length of the comment, string or character literal at the start of
/// `text`, and whether it is a comment; `None` when `text` starts with code.
fn trivia_len(text: &str) -> Option<(usize, bool)> {
    let bytes = text.as_bytes();
    match bytes.first()? {
        b'/' if bytes.get(1) == Some(&b'/') => Some((text.find('\n').unwrap_or(text.len()), true)),
        b'/' if bytes.get(1) == Some(&b'*') => Some((block_comment_len(bytes), true)),
        b'"' => Some((quoted_len(text), false)),
        b'b' if bytes.get(1) == Some(&b'"') => Some((1 + quoted_len(&text[1..]), false)),
        b'r' | b'b' => raw_string_len(text).map(|len| (len, false)),
        b'\'' => char_literal_len(text).map(|len| (len, false)),
        _ => None,
    }
}

/// The length of the `/* ... */` comment at the start of `bytes`; block
/// comments nest in Rust.
fn block_comment_len(bytes: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        match (bytes[index], bytes[index + 1]) {
            (b'/', b'*') => depth += 1,
            (b'*', b'/') => depth -= 1,
            _ => {
                index += 1;
                continue;
            }
        }
        index += 2;
        if depth == 0 {
            return index;
        }
    }
    bytes.len()
}

/// The length of the `"..."` literal at the start of `text`.
fn quoted_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut index = 1usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// The length of `r"..."`, `r#"..."#` or `br#"..."#` at the start of `text`,
/// or `None` when it starts with an identifier instead.
fn raw_string_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = usize::from(bytes[0] == b'b');
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    index += 1;
    let hashes = bytes[index..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    index += hashes;
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    let closing = format!("\"{}", "#".repeat(hashes));
    Some(
        text[index + 1..]
            .find(&closing)
            .map_or(bytes.len(), |end| index + 1 + end + closing.len()),
    )
}

/// The length of a character literal at the start of `text`, or `None` for a
/// lifetime (`'a`), which is code.
fn char_literal_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(1) == Some(&b'\\') {
        // `'\n'`, `'\''`, `'\u{..}'`: the escaped character is never the end.
        return text.get(3..)?.find('\'').map(|end| end + 4);
    }
    let width = text[1..].chars().next()?.len_utf8();
    (bytes.get(1 + width) == Some(&b'\'')).then_some(2 + width)
}

#[test]
fn code_is_told_from_comments_and_strings() {
    let source = Source::new(
        "let a = \"fn hidden(\"; // fn hidden(\n/* fn hidden( */ let c = '{'; fn shown<'a>() {}"
            .to_string(),
    );
    let view = source.view();
    assert!(!view.contains("fn hidden("));
    assert_eq!(
        view.lines_with_text("fn hidden(").len(),
        1,
        "the string, not the comments"
    );
    assert!(view.contains("fn shown<'a>("));
    let nested = Source::new("fn outer() { let s = \"}\"; if x { y(); } } fn after() {}".into());
    assert_eq!(
        nested.view().item("fn outer(").text(),
        "fn outer() { let s = \"}\"; if x { y(); } }"
    );
}

#[test]
fn cfg_test_guards_are_cut_whole_and_nothing_else() {
    let text = "struct S {\n    kept: u8,\n    #[cfg(test)]\n    /// doc\n    pub(crate) gone: HashMap<u64, String>,\n    also_kept: u8,\n}\n\
                #[cfg(test)]\nmod tests {\n    fn inside() { let s = \"}\"; }\n}\n\
                #[cfg(test)]\n#[allow(dead_code)]\nfn generic<A, B>(a: A, b: [u8; 2]) -> B { todo!() }\n\
                fn live() { #[cfg(test)] assert!(check(1, 2)); after(); }\n\
                fn call(x: u8, #[cfg(test)] y: u8) {}\n\
                #[cfg(test)]\nmod split;\nfn tail() {}\n";
    let stripped = strip_cfg_test(&Source::new(text.to_string()));
    for gone in [
        "gone",
        "fn inside",
        "fn generic",
        "check(",
        "mod split",
        "y: u8",
    ] {
        assert!(!stripped.contains(gone), "{gone:?} survived:\n{stripped}");
    }
    for kept in [
        "kept: u8",
        "also_kept: u8",
        "fn live()",
        "after();",
        "x: u8",
        "fn tail()",
    ] {
        assert!(stripped.contains(kept), "{kept:?} was cut:\n{stripped}");
    }
}
