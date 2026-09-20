//! What a library function takes and returns.
//!
//! An import has no body to read an interface off, so a call to one renders
//! with no arguments at all unless something states its prototype. radare2
//! ships that statement for two thousand library functions as `sdb` text, and
//! this reads it: the data is good, and only the lookup had any business being
//! on the other side of an FFI boundary.

use std::collections::BTreeMap;

/// One function's declared interface, in C spellings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototype {
    pub name: String,
    /// One fixed parameter per entry, in order.
    pub parameters: Vec<Parameter>,
    pub returns: String,
    /// Whether arguments continue past the fixed ones.
    pub variadic: bool,
}

/// One declared parameter: what it is, and what the declaration calls it.
///
/// The spelling decides how the call is read; the name decides only how it is
/// rendered, and a declaration that gives none renders the position instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parameter {
    pub spelling: String,
    pub name: Option<String>,
}

impl Parameter {
    pub fn new(spelling: impl Into<String>, name: Option<impl Into<String>>) -> Self {
        Self {
            spelling: spelling.into(),
            name: name.map(Into::into),
        }
    }
}

/// Every prototype the data declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prototypes {
    by_name: BTreeMap<String, Prototype>,
}

const EMBEDDED: &str = include_str!("../data/types.sdb.txt");
const EMBEDDED_LINUX: &str = include_str!("../data/types-linux.sdb.txt");
const EMBEDDED_DARWIN: &str = include_str!("../data/types-darwin.sdb.txt");

/// Which platform's own declarations apply on top of the portable ones.
///
/// `_Exit` and `__errno_location` are declared per platform, not in the table
/// every target shares, so a call to one has no prototype until the platform
/// says which set to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Darwin,
    Unknown,
}

impl Prototypes {
    /// The prototypes radare2 ships for every target.
    pub fn embedded() -> Self {
        Self::embedded_for(Platform::Unknown)
    }

    /// Those, with the ones this platform declares itself layered over them.
    pub fn embedded_for(platform: Platform) -> Self {
        let mut prototypes = Self::parse(EMBEDDED);
        let platform = match platform {
            Platform::Linux => Some(EMBEDDED_LINUX),
            Platform::Darwin => Some(EMBEDDED_DARWIN),
            Platform::Unknown => None,
        };
        if let Some(text) = platform {
            prototypes.by_name.extend(Self::parse(text).by_name);
        }
        prototypes
    }

    pub fn parse(text: &str) -> Self {
        let mut by_name: BTreeMap<String, Prototype> = BTreeMap::new();
        let mut slots: BTreeMap<String, BTreeMap<usize, Parameter>> = BTreeMap::new();
        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let Some(rest) = key.strip_prefix("func.") else {
                continue;
            };
            let Some((name, what)) = rest.rsplit_once('.') else {
                continue;
            };
            let value = value.trim();

            // `func.<name>.arg.<index>=<type>,<parameter name>`, where the
            // parameter name is presentation and the type decides how the call
            // is read.
            if let Some(name) = name.strip_suffix(".arg") {
                let Ok(index) = what.parse::<usize>() else {
                    continue;
                };
                declare(&mut by_name, name);
                let (spelling, called) = match value.split_once(',') {
                    Some((spelling, called)) => (spelling.trim(), Some(called.trim())),
                    None => (value, None),
                };
                slots.entry(name.to_owned()).or_default().insert(
                    index,
                    Parameter::new(spelling, called.filter(|called| !called.is_empty())),
                );
                continue;
            }

            match what {
                "args" => {
                    declare(&mut by_name, name);
                }
                "ret" => declare(&mut by_name, name).returns = value.to_owned(),
                _ => {}
            }
        }

        for (name, positions) in slots {
            let Some(prototype) = by_name.get_mut(&name) else {
                continue;
            };
            for parameter in positions.into_values() {
                // An empty spelling is the ellipsis: everything after it is
                // whatever the caller passes.
                if parameter.spelling.is_empty() {
                    prototype.variadic = true;
                    break;
                }
                prototype.parameters.push(parameter);
            }
        }
        Self { by_name }
    }

    /// Layer prototypes the binary itself declares over the shipped ones.
    ///
    /// What a binary's own debug information says beats what the shared table
    /// declares for the same name: the table is what a library is expected to
    /// look like, and the binary is what it is.
    pub fn declare(&mut self, prototypes: impl IntoIterator<Item = Prototype>) {
        for prototype in prototypes {
            self.by_name.insert(prototype.name.clone(), prototype);
        }
    }

    pub fn get(&self, name: &str) -> Option<&Prototype> {
        // A linked name carries at most the platform's own decoration, which
        // is one underscore where there is any: Mach-O spells `__strcpy_chk`
        // as `___strcpy_chk`, and the declaration keeps the other two. Only
        // that one is dropped. Dropping them until something matched turned
        // `__memcpy_chk` into `memcpy`, which takes one argument fewer.
        self.by_name
            .get(name)
            .or_else(|| self.by_name.get(name.strip_prefix('_')?))
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The prototype this name will be filled in for.
fn declare<'a>(by_name: &'a mut BTreeMap<String, Prototype>, name: &str) -> &'a mut Prototype {
    by_name.entry(name.to_owned()).or_insert_with(|| Prototype {
        name: name.to_owned(),
        ..Prototype::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_prototype_reads_whole() {
        let prototypes = Prototypes::embedded();
        let puts = prototypes.get("puts").expect("puts");
        assert_eq!(puts.parameters, [Parameter::new("const char *", Some("s"))]);
        assert_eq!(puts.returns, "int");
        assert!(!puts.variadic);
    }

    #[test]
    fn the_ellipsis_is_variadic_rather_than_a_parameter() {
        let prototypes = Prototypes::embedded();
        let printf = prototypes.get("printf").expect("printf");
        assert_eq!(
            printf.parameters,
            [Parameter::new("const char *", Some("format"))]
        );
        assert!(printf.variadic);
    }

    #[test]
    fn a_decorated_name_finds_its_undecorated_prototype() {
        let prototypes = Prototypes::embedded();
        assert_eq!(
            prototypes.get("_strlen").map(|p| p.returns.as_str()),
            Some("size_t")
        );
        // The declaration keeps two underscores and the linker adds a third.
        assert_eq!(
            prototypes.get("___strcpy_chk").map(|p| p.parameters.len()),
            Some(3)
        );
    }

    #[test]
    fn the_data_declares_a_few_thousand_functions() {
        let count = Prototypes::embedded().len();
        assert!(count > 500, "{count}");
    }
}
