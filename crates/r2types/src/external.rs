use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalField {
    pub name: String,
    pub offset: u64,
    pub ty: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalStruct {
    pub name: String,
    pub fields: BTreeMap<u64, ExternalField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalUnion {
    pub name: String,
    pub fields: BTreeMap<u64, ExternalField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalEnum {
    pub name: String,
    pub variants: BTreeMap<i64, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalTypedef {
    pub name: String,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAggregateKind {
    Struct,
    Union,
    Enum,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalTypeDb {
    pub structs: HashMap<String, ExternalStruct>,
    pub unions: HashMap<String, ExternalUnion>,
    pub enums: HashMap<String, ExternalEnum>,
    pub typedefs: BTreeMap<String, ExternalTypedef>,
    pub diagnostics: Vec<String>,
}

fn is_opaque_placeholder_type_name(ty: &str) -> bool {
    let lower = ty.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    let stripped = lower.strip_prefix("struct ").unwrap_or(&lower).trim_start();
    stripped.starts_with("type_0x") || lower.contains(" type_0x")
}

fn normalize_prefixed_aggregate_type(ty: &str, prefix: &str) -> Option<String> {
    let dotted = format!("{prefix}.");
    if !ty.to_ascii_lowercase().starts_with(&dotted) {
        return None;
    }
    let rest = &ty[dotted.len()..];
    let ident_len = rest
        .char_indices()
        .find_map(|(idx, ch)| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                None
            } else {
                Some(idx)
            }
        })
        .unwrap_or(rest.len());
    if ident_len == 0 {
        return None;
    }
    let raw_name = &rest[..ident_len];
    let name = raw_name.replace('.', "_");
    if name.is_empty() {
        return None;
    }
    let suffix = rest[ident_len..].trim_start();
    if suffix.is_empty() {
        Some(format!("{prefix} {name}"))
    } else {
        Some(format!("{prefix} {name} {suffix}"))
    }
}

fn normalize_primitive_alias(base: &str) -> Option<&'static str> {
    match base.to_ascii_lowercase().as_str() {
        "idx" => Some("idx_t"),
        "long" | "long int" | "longint" => Some("long"),
        "longu" | "unsigned long" | "unsigned long int" | "unsignedlong" | "unsignedlongint" => {
            Some("unsigned long")
        }
        "long long" | "long long int" | "longlong" | "longlongint" => Some("long long"),
        "long long unsigned"
        | "unsigned long long"
        | "unsigned long long int"
        | "unsignedlonglong"
        | "unsignedlonglongint"
        | "longlongu" => Some("unsigned long long"),
        "bool" | "_bool" => Some("bool"),
        "boolean" => Some("bool"),
        "uintptr_t" => Some("size_t"),
        "intptr_t" => Some("ssize_t"),
        _ => None,
    }
}

pub fn normalize_external_type_name(ty: &str) -> String {
    let spelled = normalize_type_spelling(ty);
    if spelled.trim().is_empty()
        || spelled.contains('.')
        || is_opaque_placeholder_type_name(&spelled)
    {
        return "void *".to_string();
    }
    spelled
}

fn is_type_qualifier(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "const"
            | "volatile"
            | "restrict"
            | "register"
            | "__const"
            | "__const__"
            | "__volatile"
            | "__volatile__"
            | "__restrict"
            | "__restrict__"
    )
}

fn strip_type_qualifiers(spelling: &str) -> String {
    let mut normalized = String::with_capacity(spelling.len());
    let mut start = 0usize;
    for (idx, ch) in spelling.char_indices() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            continue;
        }
        let token = &spelling[start..idx];
        if !is_type_qualifier(token) {
            normalized.push_str(token);
        }
        normalized.push(ch);
        start = idx + ch.len_utf8();
    }
    let token = &spelling[start..];
    if !is_type_qualifier(token) {
        normalized.push_str(token);
    }
    normalized
}

/// Strip the spellings radare2 decorates a type name with.
///
/// Qualifiers, its `type.` and `struct.` prefixes, and the like. This is
/// separate from `normalize_external_type_name` because that one also decides
/// that an opaque placeholder *is* `void *`, which is a judgement about what to
/// do with an unknown type rather than a fact about how it is spelled. Parsing
/// must not make that judgement: a `struct type_0x123 *` has to survive as
/// itself so the caller can require its materialization and fail closed.
pub fn normalize_type_spelling(ty: &str) -> String {
    let mut normalized = strip_type_qualifiers(ty.trim()).trim().to_string();

    loop {
        let lower = normalized.to_ascii_lowercase();
        if lower.starts_with("type.") {
            normalized = normalized[5..].trim_start().to_string();
            continue;
        }
        if lower.starts_with("struct type.") {
            normalized = format!("struct {}", normalized["struct type.".len()..].trim_start());
            continue;
        }
        if lower.starts_with("union type.") {
            normalized = format!("union {}", normalized["union type.".len()..].trim_start());
            continue;
        }
        if lower.starts_with("enum type.") {
            normalized = format!("enum {}", normalized["enum type.".len()..].trim_start());
            continue;
        }
        break;
    }

    if let Some(tagged) = normalize_prefixed_aggregate_type(&normalized, "struct") {
        normalized = tagged;
    } else if let Some(tagged) = normalize_prefixed_aggregate_type(&normalized, "union") {
        normalized = tagged;
    } else if let Some(tagged) = normalize_prefixed_aggregate_type(&normalized, "enum") {
        normalized = tagged;
    }

    let mut ptr_suffix = String::new();
    while normalized.trim_end().ends_with('*') {
        normalized = normalized.trim_end_matches('*').trim_end().to_string();
        if ptr_suffix.is_empty() {
            ptr_suffix.push_str(" *");
        } else {
            ptr_suffix.push('*');
        }
    }

    let lower = normalized.to_ascii_lowercase();
    if lower.starts_with("struct ") || lower.starts_with("union ") || lower.starts_with("enum ") {
        normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.contains('.') {
            let mut parts = normalized.splitn(2, ' ');
            let prefix = parts.next().unwrap_or("struct");
            let ident = parts.next().unwrap_or("").replace('.', "_");
            normalized = format!("{prefix} {}", ident.trim());
        }
    } else if let Some(alias) = normalize_primitive_alias(&normalized) {
        normalized = alias.to_string();
    }

    normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("{normalized}{ptr_suffix}")
}

fn aggregate_lookup_keys(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_key = |candidate: &str| {
        let key = candidate.trim().to_ascii_lowercase();
        if !key.is_empty() && !out.contains(&key) {
            out.push(key);
        }
    };

    let trimmed = name.trim();
    push_key(trimmed);
    for prefix in ["struct ", "union ", "enum "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            push_key(rest);
        }
    }
    let lower = trimmed.to_ascii_lowercase();
    for prefix in ["type.", "struct type.", "union type.", "enum type."] {
        if lower.starts_with(prefix) {
            push_key(&trimmed[prefix.len()..]);
        }
    }

    let normalized = normalize_external_type_name(trimmed);
    if normalized != "void *" {
        push_key(&normalized);
        for prefix in ["struct ", "union ", "enum "] {
            if let Some(rest) = normalized.strip_prefix(prefix) {
                push_key(rest);
            }
        }
    }

    out
}

fn normalize_typedef_name(name: &str) -> String {
    let trimmed = name.trim();
    trimmed
        .strip_prefix("typedef.")
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

impl ExternalTypeDb {
    pub fn insert_typedef(&mut self, name: impl Into<String>, target: impl Into<String>) {
        let name = normalize_typedef_name(&name.into());
        let target = target.into().trim().to_string();
        if name.is_empty() || target.is_empty() {
            return;
        }
        self.typedefs
            .insert(name.to_ascii_lowercase(), ExternalTypedef { name, target });
    }

    pub fn is_aggregate_typedef(&self, name: &str) -> bool {
        aggregate_lookup_keys(name)
            .iter()
            .any(|key| self.typedefs.contains_key(key))
            && self.resolve_typedef_aggregate(name).is_some()
    }

    /// Whether the source type database actually declares this typedef name.
    /// Parsing an identifier is not enough: callers use this to avoid minting
    /// a more-specific type from an otherwise unplaceable spelling.
    pub fn declares_typedef(&self, name: &str) -> bool {
        aggregate_lookup_keys(name)
            .iter()
            .any(|key| self.typedefs.contains_key(key))
    }

    pub fn resolve_aggregate_kind(&self, name: &str) -> Option<ExternalAggregateKind> {
        for key in aggregate_lookup_keys(name) {
            if self.structs.contains_key(&key) {
                return Some(ExternalAggregateKind::Struct);
            }
            if self.unions.contains_key(&key) {
                return Some(ExternalAggregateKind::Union);
            }
            if self.enums.contains_key(&key) {
                return Some(ExternalAggregateKind::Enum);
            }
        }
        self.resolve_typedef_aggregate(name).map(|(kind, _)| kind)
    }

    fn resolve_typedef_aggregate(&self, name: &str) -> Option<(ExternalAggregateKind, String)> {
        self.typedef_chain_keys(name).find_map(|keys| {
            keys.into_iter().find_map(|key| {
                if self.structs.contains_key(&key) {
                    Some((ExternalAggregateKind::Struct, key))
                } else if self.unions.contains_key(&key) {
                    Some((ExternalAggregateKind::Union, key))
                } else if self.enums.contains_key(&key) {
                    Some((ExternalAggregateKind::Enum, key))
                } else {
                    None
                }
            })
        })
    }

    /// The lookup keys of `name`, then of each target along its typedef chain.
    ///
    /// Each step follows the typedef entry the current keys name, and only an
    /// entry this walk has not followed before, so the chain is read to its
    /// end whatever its length and stops where a cycle closes: at most
    /// `typedefs.len() + 1` key sets, each built once.
    pub(crate) fn typedef_chain_keys(&self, name: &str) -> impl Iterator<Item = Vec<String>> + '_ {
        let mut followed = BTreeSet::new();
        std::iter::successors(Some(aggregate_lookup_keys(name)), move |keys| {
            let (key, typedef) = keys
                .iter()
                .find_map(|key| self.typedefs.get_key_value(key))?;
            followed
                .insert(key.clone())
                .then(|| aggregate_lookup_keys(&typedef.target))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_type_aliases_and_dotted_member_types() {
        assert_eq!(normalize_external_type_name("type.bool"), "bool");
        assert_eq!(normalize_external_type_name("type.LONG"), "long");
        assert_eq!(normalize_external_type_name("type.LONGU"), "unsigned long");
        assert_eq!(normalize_external_type_name("Idx"), "idx_t");
        assert_eq!(normalize_external_type_name("type.uintptr_t"), "size_t");
        assert_eq!(
            normalize_external_type_name("type.struct.IOCPU_Data *"),
            "struct IOCPU_Data *"
        );
        assert_eq!(
            normalize_external_type_name("type.IOCPU_VTable.setCPUNumber"),
            "void *"
        );
    }

    /// A struct reached through `links` typedefs, and a cycle of two beside it.
    fn typedef_chain_db(links: usize) -> ExternalTypeDb {
        let mut db = ExternalTypeDb::default();
        db.structs.insert(
            "payload".to_string(),
            ExternalStruct {
                name: "payload".to_string(),
                fields: BTreeMap::from([(
                    0,
                    ExternalField {
                        name: "first".to_string(),
                        offset: 0,
                        ty: Some("int".to_string()),
                    },
                )]),
            },
        );
        for link in 0..links {
            let target = if link + 1 == links {
                "payload".to_string()
            } else {
                format!("Link{}", link + 1)
            };
            db.insert_typedef(format!("Link{link}"), target);
        }
        db.insert_typedef("Ping", "Pong");
        db.insert_typedef("Pong", "Ping");
        db
    }

    #[test]
    fn a_typedef_chain_resolves_to_its_aggregate_at_any_length() {
        for links in [1, 40] {
            let db = typedef_chain_db(links);
            assert_eq!(
                db.resolve_aggregate_kind("Link0"),
                Some(ExternalAggregateKind::Struct),
                "a chain of {links} typedefs ends at a struct"
            );
            assert!(db.is_aggregate_typedef("Link0"));
            assert!(
                crate::analysis::external_named_aggregate_has_real_layout(&db, "Link0"),
                "a chain of {links} typedefs ends at a struct with members"
            );
            // A cycle is a typedef naming no aggregate, and the walk ends there.
            assert_eq!(db.resolve_aggregate_kind("Ping"), None);
            assert!(!crate::analysis::external_named_aggregate_has_real_layout(
                &db, "Ping"
            ));
        }
    }
}
