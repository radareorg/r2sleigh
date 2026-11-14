//! The shipped table's C spellings, read once into the declaration graph.
//!
//! The table writes each parameter as C text: `const char *`, `size_t`,
//! `FILE *`. Each spelling becomes a node of the table's [`TypeGraph`] here,
//! once, and nothing downstream parses it again. A tag the table never lays
//! out is [`Type::Opaque`]. A spelling that is not C, or names a type this
//! reading cannot state -- radare2's generic `arithmetic`, a truncated
//! function-pointer spelling -- is a refused node, and only the declaration
//! that needs it loses anything.

use std::collections::BTreeMap;

use crate::CLibrary;
use crate::types::{
    Keyword, Qualifiers, Scalar, ScalarKind, Signature, Type, TypeGraph, TypeId, Width,
};

/// Read one spelling into the graph.
pub(crate) fn read(spelling: &str, graph: &mut TypeGraph, reading: &Reading) -> TypeId {
    if let Some((returns, parameters)) = code_pointer(spelling) {
        return read_code_pointer(spelling, (returns, parameters), graph, reading);
    }
    let Some(tokens) = tokens(spelling) else {
        return graph.refused(format!("`{spelling}` is not a C type spelling"));
    };
    // Everything before the first star is the base type; each star after it
    // is one pointer, qualified by the words that follow it.
    let mut levels = tokens.split(|token| *token == "*");
    let base = levels.next().unwrap_or_default();
    let mut ty = match base_type(base, graph, reading) {
        Ok(ty) => ty,
        Err(reason) => return graph.refused(format!("`{spelling}`: {reason}")),
    };
    for level in levels {
        ty = graph.add(Type::Pointer { target: ty });
        let qualifiers = match qualifiers_of(level) {
            Some(qualifiers) => qualifiers,
            None => {
                return graph.refused(format!("`{spelling}`: a pointer is qualified by a type"));
            }
        };
        if !qualifiers.is_empty() {
            ty = graph.add(Type::Qualified {
                qualifiers,
                target: ty,
            });
        }
    }
    ty
}

/// `R (*)(P, ...)` split into `R` and the parameter list; nothing for any other spelling.
fn code_pointer(spelling: &str) -> Option<(&str, &str)> {
    let (returns, rest) = spelling.split_once("(*)")?;
    let parameters = rest.trim().strip_prefix('(')?.strip_suffix(')')?;
    Some((returns.trim(), parameters.trim()))
}

/// A pointer to code stating its return and parameters (C17 6.7.6.3): `void (*)(void *)`, as the
/// cited rows spell a callback slot (S30). A parameter list holding parentheses is refused.
fn read_code_pointer(
    spelling: &str,
    (returns, parameters): (&str, &str),
    graph: &mut TypeGraph,
    reading: &Reading,
) -> TypeId {
    if returns.contains('(') || parameters.contains('(') || parameters.contains("...") {
        return graph.refused(format!("`{spelling}`: a nested or variadic code pointer"));
    }
    let returns = read(returns, graph, reading);
    let parameters = match parameters {
        "void" => Vec::new(),
        listed => (listed.split(','))
            .map(|parameter| read(parameter.trim(), graph, reading))
            .collect(),
    };
    let code = graph.add(Type::Code(Signature {
        returns,
        parameters,
        variadic: false,
        prototyped: true,
        convention: crate::StatedConvention::Normal,
    }));
    graph.add(Type::Pointer { target: code })
}

/// The words and stars of a spelling, or nothing where it holds anything else.
fn tokens(spelling: &str) -> Option<Vec<&str>> {
    let mut tokens = Vec::new();
    let mut rest = spelling.trim();
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('*') {
            tokens.push("*");
            rest = after.trim_start();
            continue;
        }
        let end = rest
            .find(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        tokens.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    (!tokens.is_empty()).then_some(tokens)
}

fn qualifier(word: &str) -> Option<Qualifiers> {
    match word {
        "const" | "__const" | "__const__" => Some(Qualifiers::CONST),
        "volatile" | "__volatile__" => Some(Qualifiers::VOLATILE),
        "restrict" | "__restrict" | "__restrict__" => Some(Qualifiers::RESTRICT),
        _ => None,
    }
}

fn qualifiers_of(words: &[&str]) -> Option<Qualifiers> {
    words.iter().try_fold(Qualifiers::default(), |all, word| {
        Some(all.union(qualifier(word)?))
    })
}

/// The type the words before any star name, qualified as they say.
fn base_type(words: &[&str], graph: &mut TypeGraph, reading: &Reading) -> Result<TypeId, String> {
    let qualifiers = words
        .iter()
        .filter_map(|word| qualifier(word))
        .fold(Qualifiers::default(), Qualifiers::union);
    let words = words
        .iter()
        .copied()
        .filter(|word| qualifier(word).is_none())
        .collect::<Vec<_>>();
    let ty = unqualified(&words, graph, reading)?;
    Ok(match qualifiers.is_empty() {
        true => ty,
        false => graph.add(Type::Qualified {
            qualifiers,
            target: ty,
        }),
    })
}

fn unqualified(words: &[&str], graph: &mut TypeGraph, reading: &Reading) -> Result<TypeId, String> {
    let library = reading.library;
    if let [name] = words
        && let Some((kind, width)) = named_scalar(name, library)
    {
        let target = graph.add(scalar(kind, width, None));
        return Ok(graph.add(Type::Typedef {
            name: (*name).to_owned(),
            target,
        }));
    }
    // `va_list` passes as a pointer everywhere here (SysV psABI 3.5.7, AAPCS64 B.4, Microsoft and
    // Apple `char *`); its pointee stays unstated.
    if let ["va_list" | "__gnuc_va_list"] = words {
        let state = graph.add(Type::Opaque {
            keyword: Keyword::Typedef,
            tag: "va_list".to_owned(),
        });
        let target = graph.add(Type::Pointer { target: state });
        return Ok(graph.add(Type::Typedef {
            name: "va_list".to_owned(),
            target,
        }));
    }
    if let [name] = words
        && library == CLibrary::Ucrt
        && let Some(spelling) = windows_type(name)
    {
        let target = read(spelling, graph, reading);
        return Ok(graph.add(Type::Typedef {
            name: (*name).to_owned(),
            target,
        }));
    }
    if let [name] = words
        && let Some(tag) = reading.handles.get(name).copied()
    {
        let target = graph.add(Type::Opaque {
            keyword: Keyword::Struct,
            tag: tag.to_owned(),
        });
        return Ok(graph.add(Type::Typedef {
            name: (*name).to_owned(),
            target,
        }));
    }
    if let Some((kind, width)) = specified(words) {
        return Ok(graph.add(scalar(kind, width, Some(words.join(" ")))));
    }
    match words {
        [] => Err("no type is named".to_owned()),
        ["void"] => Ok(TypeId::VOID),
        // radare2's word for a parameter that is a function (`__libc_start_main`'s `main`): it
        // states no signature, so its return is refused, never `void` (S30).
        ["func"] => {
            let returns = graph.refused("`func` states no return");
            let code = graph.add(Type::Code(Signature {
                returns,
                parameters: Vec::new(),
                variadic: false,
                prototyped: false,
                convention: crate::StatedConvention::Normal,
            }));
            Ok(graph.add(Type::Pointer { target: code }))
        }
        [keyword @ ("struct" | "union" | "enum"), tag] => Ok(graph.add(Type::Opaque {
            keyword: match *keyword {
                "struct" => Keyword::Struct,
                "union" => Keyword::Union,
                _ => Keyword::Enum,
            },
            tag: (*tag).to_owned(),
        })),
        // A name the table never says anything more about.
        [name] => Ok(graph.add(Type::Opaque {
            keyword: Keyword::Typedef,
            tag: (*name).to_owned(),
        })),
        _ => Err(format!("`{}` names no type", words.join(" "))),
    }
}

fn scalar(kind: ScalarKind, width: Width, name: Option<String>) -> Type {
    Type::Scalar(Scalar { kind, width, name })
}

/// A scalar spelled with C's own specifiers, in any order, or as a fixed-width
/// integer name.
fn specified(words: &[&str]) -> Option<(ScalarKind, Width)> {
    match words {
        ["float"] => return Some((ScalarKind::Float, Width::Bits(32))),
        ["double"] => return Some((ScalarKind::Float, Width::Bits(64))),
        ["long", "double"] => return Some((ScalarKind::Float, Width::LongDouble)),
        ["_Bool" | "bool"] => return Some((ScalarKind::Bool, Width::Bits(8))),
        [name] => {
            if let Some(fixed) = fixed_width(name) {
                return Some(fixed);
            }
        }
        _ => {}
    }
    integer_specifiers(words)
}

/// `int32_t`, `uint8_t`, `__int64_t` and the rest of the family.
fn fixed_width(name: &str) -> Option<(ScalarKind, Width)> {
    let name = name.trim_start_matches('_');
    let (kind, rest) = match name.strip_prefix('u') {
        Some(rest) => (ScalarKind::Unsigned, rest),
        None => (ScalarKind::Signed, name),
    };
    let bits = rest
        .strip_prefix("int")?
        .strip_suffix("_t")?
        .parse::<u32>()
        .ok()?;
    matches!(bits, 8 | 16 | 32 | 64).then_some((kind, Width::Bits(bits)))
}

/// C's integer specifiers, whose order the language says is immaterial.
fn integer_specifiers(words: &[&str]) -> Option<(ScalarKind, Width)> {
    let mut sign = None;
    let (mut longs, mut short, mut char_, mut int) = (0u32, false, false, false);
    for word in words {
        match *word {
            "unsigned" => sign = Some(ScalarKind::Unsigned),
            "signed" => sign = Some(ScalarKind::Signed),
            "long" => longs += 1,
            "short" => short = true,
            "char" => char_ = true,
            "int" => int = true,
            _ => return None,
        }
    }
    let combined = (char_ && (short || longs > 0 || int)) || (short && longs > 0) || longs > 2;
    if combined {
        return None;
    }
    let width = match (char_, short, longs) {
        (true, _, _) => Width::Bits(8),
        (_, true, _) => Width::Bits(16),
        (_, _, 0) => Width::Bits(32),
        (_, _, 1) => Width::Long,
        _ => Width::Bits(64),
    };
    // Plain `char` is a type of its own, signed or not as the target states.
    let plain = match char_ {
        true => ScalarKind::PlainChar,
        false => ScalarKind::Signed,
    };
    Some((sign.unwrap_or(plain), width))
}

/// What the platform's own headers make a name that stands for an integer.
///
/// Only names whose width the platform states for every target it runs on are
/// here; where the width is `long`'s, an address's or `wchar_t`'s, it is said
/// that way and the target answers. A name this does not list is opaque.
fn named_scalar(name: &str, library: CLibrary) -> Option<(ScalarKind, Width)> {
    use ScalarKind::{Signed, Unsigned};
    let portable = match name {
        "wchar_t" => Some((ScalarKind::WideChar, Width::WideChar)),
        "size_t" | "uintptr_t" => Some((Unsigned, Width::Pointer)),
        "ssize_t" | "intptr_t" | "ptrdiff_t" => Some((Signed, Width::Pointer)),
        "intmax_t" => Some((Signed, Width::Bits(64))),
        "uintmax_t" => Some((Unsigned, Width::Bits(64))),
        _ => None,
    };
    let posix = |name: &str| match name {
        "pid_t" | "nl_item" | "key_t" | "sig_atomic_t" => Some((Signed, Width::Bits(32))),
        "uid_t" | "gid_t" | "id_t" | "socklen_t" | "useconds_t" => {
            Some((Unsigned, Width::Bits(32)))
        }
        "time_t" => Some((Signed, Width::Long)),
        _ => None,
    };
    portable.or_else(|| match library {
        CLibrary::Glibc => posix(name).or(match name {
            "off_t" | "clock_t" | "suseconds_t" => Some((Signed, Width::Long)),
            "off64_t" => Some((Signed, Width::Bits(64))),
            "wint_t" | "mode_t" => Some((Unsigned, Width::Bits(32))),
            "wctype_t" | "nfds_t" => Some((Unsigned, Width::Long)),
            _ => None,
        }),
        CLibrary::LibSystem => posix(name).or(match name {
            "off_t" => Some((Signed, Width::Bits(64))),
            "clock_t" => Some((Unsigned, Width::Long)),
            "wint_t" | "suseconds_t" => Some((Signed, Width::Bits(32))),
            "wctype_t" | "nfds_t" => Some((Unsigned, Width::Bits(32))),
            "mode_t" => Some((Unsigned, Width::Bits(16))),
            _ => None,
        }),
        // Bionic's `<sys/types.h>` and the kernel UAPI; `mode_t` is the kernel's, as wide as the
        // target's data model states (`KERNEL_MODE_CITATION`).
        CLibrary::Bionic => posix(name).or(match name {
            "mode_t" => Some((Unsigned, Width::KernelMode)),
            "off_t" | "clock_t" | "suseconds_t" => Some((Signed, Width::Long)),
            "off64_t" => Some((Signed, Width::Bits(64))),
            "dev_t" => Some((Unsigned, Width::Long)),
            "clockid_t" => Some((Signed, Width::Bits(32))),
            "nfds_t" | "speed_t" => Some((Unsigned, Width::Bits(32))),
            _ => None,
        }),
        CLibrary::Musl | CLibrary::Ucrt | CLibrary::Unknown => None,
    })
}

/// What Microsoft's "Windows Data Types" defines a name as, for a PE's rows. `LARGE_INTEGER` is
/// a union whose `QuadPart` is `LONGLONG`; Microsoft x64 passes an 8-byte union as that integer.
fn windows_type(name: &str) -> Option<&'static str> {
    Some(match name {
        "BOOL" => "int",
        "LONG" => "long",
        "UINT" => "unsigned int",
        "DWORD" | "ULONG" | "LCID" => "unsigned long",
        "WORD" => "unsigned short",
        "BYTE" => "unsigned char",
        "DWORD64" | "ULONGLONG" => "unsigned long long",
        "LONGLONG" | "LARGE_INTEGER" => "long long",
        "SIZE_T" | "ULONG_PTR" => "uintptr_t",
        "WCHAR" => "wchar_t",
        "HANDLE" | "HMODULE" | "PVOID" | "LPVOID" => "void *",
        "LPCVOID" => "const void *",
        "LPCSTR" | "LPCCH" => "const char *",
        "LPSTR" => "char *",
        "LPCWSTR" | "LPCWCH" | "PCNZWCH" => "const WCHAR *",
        "LPWSTR" | "LPWCH" => "WCHAR *",
        "LPDWORD" => "DWORD *",
        "PDWORD64" => "DWORD64 *",
        "LPBOOL" => "BOOL *",
        "PLARGE_INTEGER" => "LARGE_INTEGER *",
        "FARPROC" | "LPTOP_LEVEL_EXCEPTION_FILTER" | "PEXCEPTION_ROUTINE" => "func",
        "LPCPINFO" => "struct _cpinfo *",
        "LPFILETIME" => "struct _FILETIME *",
        "LPCRITICAL_SECTION" => "struct _RTL_CRITICAL_SECTION *",
        "LPSECURITY_ATTRIBUTES" => "struct _SECURITY_ATTRIBUTES *",
        "LPOVERLAPPED" => "struct _OVERLAPPED *",
        "PCONTEXT" => "struct _CONTEXT *",
        "PRUNTIME_FUNCTION" => "struct _IMAGE_RUNTIME_FUNCTION_ENTRY *",
        "PUNWIND_HISTORY_TABLE" => "struct _UNWIND_HISTORY_TABLE *",
        "PKNONVOLATILE_CONTEXT_POINTERS" => "struct _KNONVOLATILE_CONTEXT_POINTERS *",
        _ => return None,
    })
}

const HANDLES: &str = include_str!("../data/handles.txt");

/// What one C library's spellings read against: the library, and the struct tag each of its handle
/// typedefs names, read from `data/handles.txt` once per table (D391).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reading {
    pub(crate) library: CLibrary,
    handles: BTreeMap<&'static str, &'static str>,
}

impl Reading {
    /// `library`'s handle rows, one pass over the file: O(rows log rows).
    pub(crate) fn of(library: CLibrary) -> Self {
        let handles = (handle_rows())
            .filter(|(of, ..)| *of == library)
            .map(|(_, name, tag)| (name, tag))
            .collect();
        Self { library, handles }
    }
}

/// Each `data/handles.txt` row as (library, typedef, tag); a line naming no `.h` header is no row.
fn handle_rows() -> impl Iterator<Item = (CLibrary, &'static str, &'static str)> {
    HANDLES.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let [library, name, tag, header] = line.split('|').map(str::trim).collect::<Vec<_>>()[..]
        else {
            return None;
        };
        let library = match library {
            "glibc" => CLibrary::Glibc,
            "bionic" => CLibrary::Bionic,
            "musl" => CLibrary::Musl,
            "libsystem" => CLibrary::LibSystem,
            "ucrt" => CLibrary::Ucrt,
            _ => return None,
        };
        header.ends_with(".h").then_some((library, name, tag))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CDataModel;

    fn spelled(spelling: &str) -> Option<String> {
        let mut graph = TypeGraph::new();
        let id = read(spelling, &mut graph, &Reading::of(CLibrary::Glibc));
        graph.spelled(id).map(|spelled| spelled.declared)
    }

    #[test]
    fn a_spelling_reads_once_into_a_node_that_spells_it_back() {
        assert_eq!(spelled("const char *").as_deref(), Some("const char *"));
        assert_eq!(spelled("char * *").as_deref(), Some("char **"));
        assert_eq!(spelled("wchar_t* *").as_deref(), Some("wchar_t **"));
        assert_eq!(spelled("FILE *").as_deref(), Some("FILE *"));
        assert_eq!(
            spelled("struct timeval *").as_deref(),
            Some("struct timeval *")
        );
    }

    #[test]
    fn a_tag_the_table_never_lays_out_is_opaque() {
        let mut graph = TypeGraph::new();
        let file = read("FILE *", &mut graph, &Reading::of(CLibrary::Musl));
        let Some(Type::Pointer { target }) = graph.get(file) else {
            panic!("{:?}", graph.get(file));
        };
        assert!(matches!(
            graph.get(*target),
            Some(Type::Opaque { keyword: Keyword::Typedef, tag }) if tag == "FILE"
        ));
        assert_eq!(graph.size_bits(file, &CDataModel::unix(64)), Some(64));
    }

    /// The handle row: `FILE` names glibc's tag and keeps its name over it.
    #[test]
    fn a_handle_a_library_states_is_its_typedef_over_the_tag() {
        let mut graph = TypeGraph::new();
        let file = read("FILE *", &mut graph, &Reading::of(CLibrary::Glibc));
        let Some(Type::Pointer { target }) = graph.get(file) else {
            panic!("{:?}", graph.get(file));
        };
        let Some(Type::Typedef { name, target }) = graph.get(*target) else {
            panic!("{:?}", graph.get(*target));
        };
        assert_eq!(name, "FILE");
        assert!(matches!(
            graph.get(*target),
            Some(Type::Opaque { keyword: Keyword::Struct, tag }) if tag == "_IO_FILE"
        ));
        assert_eq!(graph.size_bits(file, &CDataModel::unix(64)), Some(64));
        assert_eq!(
            graph.spelled(file).map(|s| s.declared).as_deref(),
            Some("FILE *")
        );
    }

    /// Every handle row parses and cites its header (D391); no handle tag is stated in code.
    #[test]
    fn every_handle_row_parses_and_names_its_header() {
        let rows = HANDLES
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
            .count();
        assert_eq!(handle_rows().count(), rows);
        assert_eq!(Reading::of(CLibrary::LibSystem).handles.get("DIR"), None);
        assert_eq!(Reading::of(CLibrary::Musl).handles.get("FILE"), None);
        let bionic = Reading::of(CLibrary::Bionic);
        assert_eq!(bionic.handles.get("FILE"), Some(&"__sFILE"));
    }

    #[test]
    fn a_platform_name_for_an_integer_has_the_width_the_target_gives_it() {
        let mut graph = TypeGraph::new();
        let size = read("size_t", &mut graph, &Reading::of(CLibrary::Unknown));
        assert_eq!(graph.size_bits(size, &CDataModel::unix(64)), Some(64));
        assert_eq!(graph.size_bits(size, &CDataModel::unix(32)), Some(32));
        let long = read("unsigned long", &mut graph, &Reading::of(CLibrary::Unknown));
        assert_eq!(graph.size_bits(long, &CDataModel::unix(32)), Some(32));
        let mode = read("mode_t", &mut graph, &Reading::of(CLibrary::LibSystem));
        assert_eq!(graph.size_bits(mode, &CDataModel::unix(64)), Some(16));
    }

    #[test]
    fn what_is_not_a_c_spelling_is_refused_by_itself() {
        let mut graph = TypeGraph::new();
        for spelling in [
            "int(*compar)(const void *",
            "struct std::type_info *",
            "long char",
        ] {
            let id = read(spelling, &mut graph, &Reading::of(CLibrary::Glibc));
            assert!(
                matches!(graph.get(id), Some(Type::Refused(_))),
                "{spelling}: {:?}",
                graph.get(id)
            );
        }
        // A name the table never defines is a tag, not a refusal: a pointer
        // to it is still a pointer.
        let generic = read("arithmetic", &mut graph, &Reading::of(CLibrary::Glibc));
        assert!(matches!(graph.get(generic), Some(Type::Opaque { .. })));
    }
}
