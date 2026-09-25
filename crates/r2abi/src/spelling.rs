//! The shipped table's C spellings, read once into the declaration graph.
//!
//! The table writes each parameter as C text: `const char *`, `size_t`,
//! `FILE *`. Each spelling becomes a node of the table's [`TypeGraph`] here,
//! once, and nothing downstream parses it again. A tag the table never lays
//! out is [`Type::Opaque`]. A spelling that is not C, or names a type this
//! reading cannot state -- radare2's generic `arithmetic`, a truncated
//! function-pointer spelling -- is a refused node, and only the declaration
//! that needs it loses anything.

use crate::Platform;
use crate::types::{
    Keyword, Qualifiers, Scalar, ScalarKind, Signature, Type, TypeGraph, TypeId, Width,
};

/// Read one spelling into the graph.
pub(crate) fn read(spelling: &str, graph: &mut TypeGraph, platform: Platform) -> TypeId {
    let Some(tokens) = tokens(spelling) else {
        return graph.refused(format!("`{spelling}` is not a C type spelling"));
    };
    // Everything before the first star is the base type; each star after it
    // is one pointer, qualified by the words that follow it.
    let mut levels = tokens.split(|token| *token == "*");
    let base = levels.next().unwrap_or_default();
    let mut ty = match base_type(base, graph, platform) {
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
fn base_type(words: &[&str], graph: &mut TypeGraph, platform: Platform) -> Result<TypeId, String> {
    let qualifiers = words
        .iter()
        .filter_map(|word| qualifier(word))
        .fold(Qualifiers::default(), Qualifiers::union);
    let words = words
        .iter()
        .copied()
        .filter(|word| qualifier(word).is_none())
        .collect::<Vec<_>>();
    let ty = unqualified(&words, graph, platform)?;
    Ok(match qualifiers.is_empty() {
        true => ty,
        false => graph.add(Type::Qualified {
            qualifiers,
            target: ty,
        }),
    })
}

fn unqualified(
    words: &[&str],
    graph: &mut TypeGraph,
    platform: Platform,
) -> Result<TypeId, String> {
    if let [name] = words
        && let Some((kind, width)) = named_scalar(name, platform)
    {
        let target = graph.add(scalar(kind, width, None));
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
        // The table's word for a parameter that is a function: `atexit`'s
        // handler, `__libc_start_main`'s `main`. It states no signature.
        ["func"] => {
            let code = graph.add(Type::Code(Signature {
                returns: TypeId::VOID,
                parameters: Vec::new(),
                variadic: false,
                prototyped: false,
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
    Some((sign.unwrap_or(ScalarKind::Signed), width))
}

/// What the platform's own headers make a name that stands for an integer.
///
/// Only names whose width the platform states for every target it runs on are
/// here; where the width is `long`'s or an address's, it is said that way and
/// the target answers. A name this does not list is opaque.
fn named_scalar(name: &str, platform: Platform) -> Option<(ScalarKind, Width)> {
    use ScalarKind::{Signed, Unsigned};
    let portable = match name {
        "size_t" | "uintptr_t" => Some((Unsigned, Width::Pointer)),
        "ssize_t" | "intptr_t" | "ptrdiff_t" => Some((Signed, Width::Pointer)),
        "intmax_t" => Some((Signed, Width::Bits(64))),
        "uintmax_t" => Some((Unsigned, Width::Bits(64))),
        _ => None,
    };
    let posix = |name: &str| match name {
        "pid_t" | "nl_item" | "key_t" | "wchar_t" | "sig_atomic_t" => {
            Some((Signed, Width::Bits(32)))
        }
        "uid_t" | "gid_t" | "id_t" | "socklen_t" | "useconds_t" => {
            Some((Unsigned, Width::Bits(32)))
        }
        "time_t" => Some((Signed, Width::Long)),
        _ => None,
    };
    portable.or_else(|| match platform {
        Platform::Linux => posix(name).or(match name {
            "off_t" | "clock_t" | "suseconds_t" => Some((Signed, Width::Long)),
            "off64_t" => Some((Signed, Width::Bits(64))),
            "wint_t" | "mode_t" => Some((Unsigned, Width::Bits(32))),
            "wctype_t" | "nfds_t" => Some((Unsigned, Width::Long)),
            _ => None,
        }),
        Platform::Darwin => posix(name).or(match name {
            "off_t" => Some((Signed, Width::Bits(64))),
            "clock_t" => Some((Unsigned, Width::Long)),
            "wint_t" | "suseconds_t" => Some((Signed, Width::Bits(32))),
            "wctype_t" | "nfds_t" => Some((Unsigned, Width::Bits(32))),
            "mode_t" => Some((Unsigned, Width::Bits(16))),
            _ => None,
        }),
        Platform::Unknown => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DataModel;

    fn spelled(spelling: &str) -> Option<String> {
        let mut graph = TypeGraph::new();
        let id = read(spelling, &mut graph, Platform::Linux);
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
        let file = read("FILE *", &mut graph, Platform::Linux);
        let Some(Type::Pointer { target }) = graph.get(file) else {
            panic!("{:?}", graph.get(file));
        };
        assert!(matches!(
            graph.get(*target),
            Some(Type::Opaque { keyword: Keyword::Typedef, tag }) if tag == "FILE"
        ));
        assert_eq!(graph.size_bits(file, &DataModel::unix(64)), Some(64));
    }

    #[test]
    fn a_platform_name_for_an_integer_has_the_width_the_target_gives_it() {
        let mut graph = TypeGraph::new();
        let size = read("size_t", &mut graph, Platform::Unknown);
        assert_eq!(graph.size_bits(size, &DataModel::unix(64)), Some(64));
        assert_eq!(graph.size_bits(size, &DataModel::unix(32)), Some(32));
        let long = read("unsigned long", &mut graph, Platform::Unknown);
        assert_eq!(graph.size_bits(long, &DataModel::unix(32)), Some(32));
        let mode = read("mode_t", &mut graph, Platform::Darwin);
        assert_eq!(graph.size_bits(mode, &DataModel::unix(64)), Some(16));
    }

    #[test]
    fn what_is_not_a_c_spelling_is_refused_by_itself() {
        let mut graph = TypeGraph::new();
        for spelling in [
            "int(*compar)(const void *",
            "struct std::type_info *",
            "long char",
        ] {
            let id = read(spelling, &mut graph, Platform::Linux);
            assert!(
                matches!(graph.get(id), Some(Type::Refused(_))),
                "{spelling}: {:?}",
                graph.get(id)
            );
        }
        // A name the table never defines is a tag, not a refusal: a pointer
        // to it is still a pointer.
        let generic = read("arithmetic", &mut graph, Platform::Linux);
        assert!(matches!(graph.get(generic), Some(Type::Opaque { .. })));
    }
}
