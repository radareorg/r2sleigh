use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalTypeDb {
    pub structs: HashMap<String, ExternalStruct>,
    pub unions: HashMap<String, ExternalUnion>,
    pub enums: HashMap<String, ExternalEnum>,
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
    let mut normalized = ty.trim().to_string();
    if normalized.is_empty() || is_opaque_placeholder_type_name(&normalized) {
        return "void *".to_string();
    }

    for qualifier in ["const", "volatile", "restrict", "register"] {
        normalized = normalized
            .split_whitespace()
            .filter(|part| !part.eq_ignore_ascii_case(qualifier))
            .collect::<Vec<_>>()
            .join(" ");
    }

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
    } else {
        if let Some(alias) = normalize_primitive_alias(&normalized) {
            normalized = alias.to_string();
        }
        if normalized.contains('.') {
            return "void *".to_string();
        }
    }

    normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() || is_opaque_placeholder_type_name(&normalized) {
        return "void *".to_string();
    }
    format!("{normalized}{ptr_suffix}")
}

fn normalize_aggregate_name(name: &str, prefix: &str) -> String {
    let normalized = normalize_external_type_name(name);
    normalized
        .strip_prefix(&format!("{prefix} "))
        .unwrap_or(name)
        .trim()
        .to_string()
}

impl ExternalTypeDb {
    pub fn from_tsj_json(json_str: &str) -> Self {
        let trimmed = json_str.trim();
        if trimmed.is_empty() || trimmed == "{}" || trimmed == "[]" {
            return Self::default();
        }

        let mut out = Self::default();
        let value = match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => v,
            Err(e) => {
                out.diagnostics
                    .push(format!("failed to parse tsj payload: {e}"));
                return out;
            }
        };

        out.walk_value(&value);
        out
    }

    fn walk_value(&mut self, value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.walk_value(item);
                }
            }
            Value::Object(map) => {
                if let Some(name) = map
                    .get("name")
                    .or_else(|| map.get("type"))
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                {
                    if let Some(mut st) = self.parse_struct_entry(name, map) {
                        let key = st.name.clone().to_ascii_lowercase();
                        self.structs
                            .entry(key)
                            .and_modify(|existing| merge_struct(existing, &st))
                            .or_insert_with(|| {
                                if st.fields.is_empty() {
                                    st.fields = BTreeMap::new();
                                }
                                st
                            });
                    }
                    if let Some(mut un) = self.parse_union_entry(name, map) {
                        let key = un.name.clone().to_ascii_lowercase();
                        self.unions
                            .entry(key)
                            .and_modify(|existing| merge_union(existing, &un))
                            .or_insert_with(|| {
                                if un.fields.is_empty() {
                                    un.fields = BTreeMap::new();
                                }
                                un
                            });
                    }
                    if let Some(mut en) = self.parse_enum_entry(name, map) {
                        let key = en.name.clone().to_ascii_lowercase();
                        self.enums
                            .entry(key)
                            .and_modify(|existing| merge_enum(existing, &en))
                            .or_insert_with(|| {
                                if en.variants.is_empty() {
                                    en.variants = BTreeMap::new();
                                }
                                en
                            });
                    }
                }

                for child in map.values() {
                    self.walk_value(child);
                }
            }
            _ => {}
        }
    }

    fn parse_struct_entry(
        &mut self,
        fallback_name: &str,
        map: &serde_json::Map<String, Value>,
    ) -> Option<ExternalStruct> {
        let kind = map.get("kind").and_then(Value::as_str).unwrap_or("");
        let type_tag = map.get("type").and_then(Value::as_str).unwrap_or("");
        let is_struct = kind.eq_ignore_ascii_case("struct")
            || type_tag.eq_ignore_ascii_case("struct")
            || map.contains_key("members")
            || map.contains_key("fields");

        if !is_struct {
            return None;
        }

        let struct_name = map
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(fallback_name)
            .to_string();

        let mut out = ExternalStruct {
            name: normalize_aggregate_name(&struct_name, "struct"),
            fields: BTreeMap::new(),
        };

        let mut parse_members = |members: &Value| {
            if let Value::Array(entries) = members {
                for entry in entries {
                    let Value::Object(member) = entry else {
                        continue;
                    };
                    let Some(offset) = member
                        .get("offset")
                        .and_then(|v| v.as_u64().or_else(|| parse_u64(v.as_str())))
                    else {
                        continue;
                    };

                    let name = member
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("field_{offset:x}"));

                    let ty = member
                        .get("type")
                        .and_then(Value::as_str)
                        .map(normalize_external_type_name)
                        .or_else(|| {
                            member
                                .get("fmt")
                                .and_then(Value::as_str)
                                .map(normalize_external_type_name)
                        });

                    out.fields
                        .entry(offset)
                        .or_insert(ExternalField { name, offset, ty });
                }
            }
        };

        if let Some(members) = map.get("members") {
            parse_members(members);
        }
        if let Some(fields) = map.get("fields") {
            parse_members(fields);
        }

        Some(out)
    }

    fn parse_union_entry(
        &mut self,
        fallback_name: &str,
        map: &serde_json::Map<String, Value>,
    ) -> Option<ExternalUnion> {
        let kind = map.get("kind").and_then(Value::as_str).unwrap_or("");
        let type_tag = map.get("type").and_then(Value::as_str).unwrap_or("");
        let is_union = kind.eq_ignore_ascii_case("union")
            || type_tag.eq_ignore_ascii_case("union")
            || (map.contains_key("members")
                && map
                    .get("name")
                    .and_then(Value::as_str)
                    .map(|name| name.contains("union"))
                    .unwrap_or(false));
        if !is_union {
            return None;
        }

        let union_name = map
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(fallback_name)
            .to_string();
        let mut out = ExternalUnion {
            name: normalize_aggregate_name(&union_name, "union"),
            fields: BTreeMap::new(),
        };

        let mut parse_members = |members: &Value| {
            if let Value::Array(entries) = members {
                for entry in entries {
                    let Value::Object(member) = entry else {
                        continue;
                    };
                    let offset = member
                        .get("offset")
                        .and_then(|v| v.as_u64().or_else(|| parse_u64(v.as_str())))
                        .unwrap_or(0);
                    let name = member
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("field_{offset:x}"));
                    let ty = member
                        .get("type")
                        .and_then(Value::as_str)
                        .map(normalize_external_type_name)
                        .or_else(|| {
                            member
                                .get("fmt")
                                .and_then(Value::as_str)
                                .map(normalize_external_type_name)
                        });
                    out.fields
                        .entry(offset)
                        .or_insert(ExternalField { name, offset, ty });
                }
            }
        };

        if let Some(members) = map.get("members") {
            parse_members(members);
        }
        if let Some(fields) = map.get("fields") {
            parse_members(fields);
        }
        Some(out)
    }

    fn parse_enum_entry(
        &mut self,
        fallback_name: &str,
        map: &serde_json::Map<String, Value>,
    ) -> Option<ExternalEnum> {
        let kind = map.get("kind").and_then(Value::as_str).unwrap_or("");
        let type_tag = map.get("type").and_then(Value::as_str).unwrap_or("");
        let is_enum = kind.eq_ignore_ascii_case("enum")
            || type_tag.eq_ignore_ascii_case("enum")
            || map.contains_key("values")
            || map.contains_key("cases");
        if !is_enum {
            return None;
        }

        let enum_name = map
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(fallback_name)
            .to_string();
        let mut out = ExternalEnum {
            name: normalize_aggregate_name(&enum_name, "enum"),
            variants: BTreeMap::new(),
        };

        let mut parse_variants = |values: &Value| {
            if let Value::Array(entries) = values {
                for (idx, entry) in entries.iter().enumerate() {
                    let Value::Object(variant) = entry else {
                        continue;
                    };
                    let name = variant
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("case_{}", idx));
                    let value = variant
                        .get("value")
                        .or_else(|| variant.get("val"))
                        .or_else(|| variant.get("offset"))
                        .and_then(|v| v.as_i64().or_else(|| parse_i64(v.as_str())))
                        .unwrap_or(idx as i64);
                    out.variants.entry(value).or_insert(name);
                }
            }
        };

        if let Some(values) = map.get("values") {
            parse_variants(values);
        }
        if let Some(cases) = map.get("cases") {
            parse_variants(cases);
        }
        if let Some(members) = map.get("members") {
            parse_variants(members);
        }
        Some(out)
    }
}

fn parse_u64(input: Option<&str>) -> Option<u64> {
    let raw = input?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    raw.parse::<u64>().ok()
}

fn parse_i64(input: Option<&str>) -> Option<i64> {
    let raw = input?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    raw.parse::<i64>().ok()
}

fn merge_struct(target: &mut ExternalStruct, source: &ExternalStruct) {
    for (offset, field) in &source.fields {
        target
            .fields
            .entry(*offset)
            .or_insert_with(|| field.clone());
    }
}

fn merge_union(target: &mut ExternalUnion, source: &ExternalUnion) {
    for (offset, field) in &source.fields {
        target
            .fields
            .entry(*offset)
            .or_insert_with(|| field.clone());
    }
}

fn merge_enum(target: &mut ExternalEnum, source: &ExternalEnum) {
    for (value, name) in &source.variants {
        target
            .variants
            .entry(*value)
            .or_insert_with(|| name.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_malformed_tsj_is_tolerant() {
        let db = ExternalTypeDb::from_tsj_json("{not-json");
        assert!(db.structs.is_empty());
        assert!(!db.diagnostics.is_empty());
    }

    #[test]
    fn parse_struct_members_from_json() {
        let json = r#"
        {
          "types": [
            {
              "kind": "struct",
              "name": "demo",
              "members": [
                {"name": "first", "offset": 0, "type": "int"},
                {"name": "second", "offset": 8, "type": "char *"}
              ]
            }
          ]
        }
        "#;
        let db = ExternalTypeDb::from_tsj_json(json);
        let st = db.structs.get("demo").expect("demo struct missing");
        assert_eq!(st.fields.len(), 2);
        assert_eq!(
            st.fields.get(&8).map(|field| field.name.as_str()),
            Some("second")
        );
    }

    #[test]
    fn parse_union_and_enum_from_json() {
        let json = r#"
        {
          "types": [
            {
              "kind": "union",
              "name": "word",
              "members": [
                {"name": "u32v", "offset": 0, "type": "uint32_t"},
                {"name": "bytes", "offset": 0, "type": "uint8_t[4]"}
              ]
            },
            {
              "kind": "enum",
              "name": "state",
              "values": [
                {"name": "STATE_IDLE", "value": 0},
                {"name": "STATE_CONNECTING", "value": 1}
              ]
            }
          ]
        }
        "#;
        let db = ExternalTypeDb::from_tsj_json(json);
        let un = db.unions.get("word").expect("word union missing");
        assert_eq!(un.fields.get(&0).map(|f| f.name.as_str()), Some("u32v"));
        let en = db.enums.get("state").expect("state enum missing");
        assert_eq!(
            en.variants.get(&1).map(|name| name.as_str()),
            Some("STATE_CONNECTING")
        );
    }

    #[test]
    fn normalize_type_aliases_and_dotted_member_types() {
        assert_eq!(normalize_external_type_name("type.bool"), "bool");
        assert_eq!(normalize_external_type_name("type.LONG"), "long");
        assert_eq!(normalize_external_type_name("type.LONGU"), "unsigned long");
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

    #[test]
    fn parse_kernel_style_struct_fields_are_canonicalized() {
        let json = r#"
        {
          "types": [
            {
              "kind": "struct",
              "name": "type.struct.IOCPU_Data",
              "members": [
                {"name": "meta", "offset": 0, "type": "type.struct.OSMetaClass_VTable *"},
                {"name": "setter", "offset": 8, "type": "type.IOCPU_VTable.setCPUNumber"},
                {"name": "count", "offset": 16, "type": "type.LONGU"}
              ]
            }
          ]
        }
        "#;
        let db = ExternalTypeDb::from_tsj_json(json);
        let st = db.structs.get("iocpu_data").expect("struct missing");
        assert_eq!(st.name, "IOCPU_Data");
        assert_eq!(
            st.fields.get(&0).and_then(|f| f.ty.as_deref()),
            Some("struct OSMetaClass_VTable *")
        );
        assert_eq!(
            st.fields.get(&8).and_then(|f| f.ty.as_deref()),
            Some("void *")
        );
        assert_eq!(
            st.fields.get(&16).and_then(|f| f.ty.as_deref()),
            Some("unsigned long")
        );
    }
}
