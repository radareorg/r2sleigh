//! What an Itanium C++ ABI mangled name states (5.1): its parameters, whose rows return
//! `Unproven`, and its spelling as `c++filt` prints it. A name this does not parse is refused
//! whole (doc/adr-call-boundary.md, S13 as built; doc/adr-display.md, "Round 15 as built: names").

use std::rc::Rc;

/// Whether a function takes an implicit object parameter (`this`) before its explicit ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// A namespace-scope function: the name has no enclosing class.
    None,
    /// A non-static member: a constructor, a destructor, a cv- or ref-qualified member, or an
    /// operator of a class (C++17 [over.oper]). Holds the spelling of `this`.
    This(String),
    /// Nested in a scope the name does not say is a class, or a member it does not say is
    /// non-static. Holds the spelling `this` takes where a cited row says it is one.
    Unstated(String),
}

/// Whether the explicit parameters (after `this`) are all a call passes before its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Passing {
    /// The result is encoded and returns in registers, or there is none (C1, D0, D1).
    Stated,
    /// No result is encoded: one returned in memory passes a hidden pointer first (Itanium C++
    /// ABI 3.1.3), in an argument register on SysV x86-64 and Microsoft x64.
    HiddenResultUnstated,
    /// A base-object constructor or destructor (C2, D2) of a class with virtual bases takes a VTT
    /// after `this` (Itanium C++ ABI 2.6.2); C3, D4 and D5 are not read either.
    VttUnstated,
}

/// What one mangled function name states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mangled {
    pub object: Object,
    pub passing: Passing,
    /// Each explicit parameter, spelled as C (a reference is its pointer, Itanium C++ ABI 3.1.2).
    pub parameters: Vec<String>,
    /// The parameter list ends in `...` (`z`).
    pub variadic: bool,
    /// The whole name as `c++filt` reads it, where every production in it is one it spells.
    shown: Option<Shown>,
}

impl Mangled {
    /// The name as `c++filt` (GNU binutils, `DMGL_PARAMS | DMGL_ANSI | DMGL_VERBOSE`) prints it,
    /// or `None` where a production in it is one this does not spell: such a name stays mangled.
    /// O(name length).
    pub fn spelled(&self) -> Option<String> {
        let shown = self.shown.as_ref()?;
        let mut printer = Printer::default();
        printer.encoding(shown);
        for clone in &shown.clones {
            printer.out.push_str(" [clone ");
            printer.out.push_str(clone);
            printer.out.push(']');
        }
        (!printer.failed).then_some(printer.out)
    }
}

/// The parameters `name` states, or `None` where it is not a function's mangled name this reads.
/// O(name length), with substitutions looked up by index.
pub fn parse(name: &str) -> Option<Mangled> {
    let (base, suffix) = name.split_at(name.find(['.', '@']).unwrap_or(name.len()));
    let body = base.strip_prefix("_Z")?;
    let mut parser = Parser {
        text: body.as_bytes(),
        at: 0,
        substitutions: Vec::new(),
        template_args: None,
        last_name: None,
        unspelled: false,
    };
    let function = parser.name()?;
    parser.template_args.clone_from(&function.template_args);
    // A template function's first type is its result (5.1.3); a conversion names its own.
    let (result, shown_result) = match (&function.special, function.template_args.is_some()) {
        (Some(Special::Conversion(ty)), _) => (Some(ty.clone()), None),
        (None, true) => {
            let (ty, shown) = parser.ty()?;
            (Some(ty), Some(shown))
        }
        _ => (None, None),
    };
    let passing = match (&function.special, result) {
        (Some(Special::Structor(b'1' | b'0')), _) => Passing::Stated,
        (Some(Special::Structor(_)), _) => Passing::VttUnstated,
        (_, Some(result)) if result.in_registers() => Passing::Stated,
        _ => Passing::HiddenResultUnstated,
    };
    let (mut parameters, mut variadic, mut none) = (Vec::new(), false, false);
    let mut shown_parameters = Vec::new();
    while !parser.done() {
        match parser.peek() {
            Some(b'v') if parameters.is_empty() && parser.at + 1 == parser.text.len() => {
                parser.at += 1;
                none = true;
            }
            Some(b'z') => {
                parser.at += 1;
                variadic = true;
                break;
            }
            _ => {
                let (ty, shown) = parser.ty()?;
                parameters.push(ty.spell()?);
                shown_parameters.push(shown);
            }
        }
    }
    let clones = clone_suffixes(suffix);
    let shown = (!parser.unspelled && parser.done())
        .then_some(clones)
        .flatten()
        .map(|clones| Shown {
            name: function.shown,
            this: function.this,
            function: FunctionNode {
                result: shown_result,
                parameters: shown_parameters,
                variadic,
            },
            clones,
        });
    (variadic || none || !parameters.is_empty()).then_some(Mangled {
        object: function.object,
        passing,
        parameters,
        variadic,
        shown,
    })
}

/// The clone suffixes after an encoding (`.cold`, `.constprop.0`), each as `c++filt` prints it
/// in `[clone ...]`: `.` and `[a-z0-9_]+`, then `.` and digits any number of times. A suffix
/// that is not one, or a symbol version after `@`, leaves the name unspelled.
fn clone_suffixes(mut rest: &str) -> Option<Vec<String>> {
    let lower = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_';
    let mut clones = Vec::new();
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        if bytes[0] != b'.' || !bytes.get(1).is_some_and(lower) {
            return None;
        }
        let mut end = 2 + bytes[2..].iter().take_while(|byte| lower(byte)).count();
        while bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
            end += 2 + bytes[end + 2..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
        }
        clones.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    Some(clones)
}

/// A type as far as a C spelling needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ty {
    Builtin(&'static str),
    /// A class or enum, by its last component; `class` where the name proves a class.
    Named {
        name: String,
        class: bool,
    },
    Pointer(Box<Ty>),
    Qualified(&'static str, Box<Ty>),
    Function,
}

impl Ty {
    /// A result no ABI here returns in memory: `void`, a builtin this reads, a pointer or a
    /// reference. A class or enum by value may be returned in memory.
    fn in_registers(&self) -> bool {
        match self {
            Self::Builtin(_) | Self::Pointer(_) => true,
            Self::Qualified(_, target) => target.in_registers(),
            Self::Named { .. } | Self::Function => false,
        }
    }

    fn spell(&self) -> Option<String> {
        Some(match self {
            Self::Builtin(spelling) => (*spelling).to_owned(),
            Self::Named { name, .. } => name.clone(),
            Self::Pointer(target) => match &**target {
                Self::Function => "func".to_owned(),
                target => format!("{} *", target.spell()?),
            },
            // A pointer's own qualifier is no part of a prototype's type (data/README.md).
            Self::Qualified(_, target) if matches!(**target, Self::Pointer(_) | Self::Function) => {
                target.spell()?
            }
            Self::Qualified(qualifier, target) => format!("{qualifier} {}", target.spell()?),
            Self::Function => "func".to_owned(),
        })
    }
}

/// A type or name as `c++filt` prints it: the demangler's components (libiberty `cp-demangle.c`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A source name, an operator, a constructor's or destructor's name, or an expansion.
    Name(Rc<str>),
    Builtin(&'static str),
    /// `scope::name`.
    Scoped(Rc<Node>, Rc<Node>),
    /// `name<arguments>`.
    Template(Rc<Node>, Rc<[Node]>),
    /// `name[abi:tag]...` (5.1.2).
    Tagged(Rc<Node>, Rc<[String]>),
    Pointer(Rc<Node>),
    Reference(Rc<Node>),
    RvalueReference(Rc<Node>),
    Const(Rc<Node>),
    Volatile(Rc<Node>),
    /// A function type's ref-qualifier, printed after its parameters.
    RefQualified(&'static str, Rc<Node>),
    Function(Rc<FunctionNode>),
    /// An array type by its dimension's text, which may be empty.
    Array(Rc<str>, Rc<Node>),
    /// A literal template argument: its type and the text of its value (5.1.6).
    Literal(Rc<Node>, Rc<str>),
    /// A conversion operator by the type it converts to.
    Conversion(Rc<Node>),
}

impl Node {
    fn name(text: &str) -> Self {
        Self::Name(text.into())
    }

    fn scoped(scope: Self, name: Self) -> Self {
        Self::Scoped(Rc::new(scope), Rc::new(name))
    }

    fn template(name: Self, arguments: &[Both]) -> Self {
        let arguments = arguments.iter().map(|(_, shown)| shown.clone()).collect();
        Self::Template(Rc::new(name), arguments)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionNode {
    result: Option<Node>,
    /// Empty for a list that is only `v`.
    parameters: Vec<Node>,
    variadic: bool,
}

/// A whole encoding: its name, the qualifiers `this` takes, its type, and its clone suffixes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shown {
    name: Node,
    /// The qualifiers printed after the parameters, in the order they print.
    this: Vec<&'static str>,
    function: FunctionNode,
    clones: Vec<String>,
}

/// A type in both readings: as a C prototype spells it and as `c++filt` prints it.
type Both = (Ty, Node);

/// A function's name as it decides the object parameter and the template arguments.
struct Name {
    object: Object,
    template_args: Option<Vec<Both>>,
    /// A constructor, destructor or conversion, whose template arguments encode no result.
    special: Option<Special>,
    shown: Node,
    this: Vec<&'static str>,
}

/// A name whose result the template arguments do not encode.
#[derive(Debug, Clone)]
enum Special {
    /// A constructor (`C1`, `C2`, `C3`) or destructor (`D0` to `D5`) by its variant digit; `0`
    /// stands for `D0`, and a constructor's `1` and a destructor's `1` read alike.
    Structor(u8),
    /// A conversion, by the type it converts to.
    Conversion(Ty),
}

/// One component of a nested name.
enum Component {
    Source(String),
    Constructor(u8),
    Destructor(u8),
    /// An operator by its two-letter code.
    Operator([u8; 2]),
    /// A conversion, by the type it converts to.
    Conversion(Ty),
}

/// The components of a nested name as far as they are read.
#[derive(Default)]
struct Prefixes {
    /// What the components so far name.
    current: Option<Both>,
    /// `current` is a substitution, already a candidate.
    fresh: bool,
    /// The scope the last component is named in.
    enclosing: Option<Ty>,
    last: Option<Component>,
    template_args: Option<Vec<Both>>,
    /// An `St` was read and the next component is in `std`.
    std: bool,
}

impl Prefixes {
    /// A substitution or template parameter names everything so far afresh.
    fn restart(&mut self, ty: Both) {
        (self.current, self.fresh) = (Some(ty), true);
        (self.last, self.template_args) = (None, None);
    }

    /// The function the components name, its `this` cv- or ref-qualified where `qualified`.
    fn into_name(self, qualified: bool, constant: bool, shown: Node) -> Option<Name> {
        let this = |ty: &Ty| -> Option<String> {
            let class = match constant {
                true => Ty::Qualified("const", Box::new(ty.clone())),
                false => ty.clone(),
            };
            Ty::Pointer(Box::new(class)).spell()
        };
        let enclosing_is_class = matches!(self.enclosing, Some(Ty::Named { class: true, .. }));
        let special = match &self.last {
            Some(Component::Constructor(variant) | Component::Destructor(variant)) => {
                Some(Special::Structor(*variant))
            }
            Some(Component::Conversion(ty)) => Some(Special::Conversion(ty.clone())),
            _ => None,
        };
        let object = match (&self.enclosing, &self.last) {
            (None, _) => Object::None,
            (Some(ty), _) if qualified || special.is_some() => Object::This(this(ty)?),
            // [over.oper]: an operator other than new, delete, () and [] is a non-static member
            // where it is a member at all.
            (Some(ty), Some(Component::Operator(code)))
                if enclosing_is_class
                    && !matches!(code, b"nw" | b"na" | b"dl" | b"da" | b"cl" | b"ix") =>
            {
                Object::This(this(ty)?)
            }
            (Some(ty), _) => Object::Unstated(this(ty)?),
        };
        Some(Name {
            object,
            template_args: self.template_args,
            special,
            shown,
            this: Vec::new(),
        })
    }
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    /// Every substitution candidate in order (5.1.10): `S_` is the first, `S0_` the second.
    substitutions: Vec<Both>,
    /// The function's own template arguments, which `T_` names.
    template_args: Option<Vec<Both>>,
    /// The last source name read outside template arguments, which a constructor or destructor
    /// is named by (libiberty `d_info::last_name`).
    last_name: Option<Rc<str>>,
    /// A production was read that the spelling does not state exactly.
    unspelled: bool,
}

impl Parser<'_> {
    fn done(&self) -> bool {
        self.at >= self.text.len()
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        self.at += usize::from(found);
        found
    }

    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(count)?;
        let taken = self.text.get(self.at..end)?;
        self.at = end;
        Some(taken)
    }

    fn number(&mut self) -> Option<usize> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        std::str::from_utf8(&self.text[start..self.at])
            .ok()?
            .parse()
            .ok()
    }

    /// The text from `start` to here, which is ASCII wherever the name is.
    fn text_from(&mut self, start: usize) -> Rc<str> {
        let text = std::str::from_utf8(&self.text[start..self.at]);
        self.unspelled |= text.is_err();
        text.unwrap_or_default().into()
    }

    /// A source name and its ABI tags, which name no new entity (5.1.2).
    fn source_name(&mut self) -> Option<(String, Node)> {
        let length = self.number()?;
        let name = std::str::from_utf8(self.take(length)?).ok()?.to_owned();
        // `_GLOBAL_` then `.`, `_` or `$`, then `N` is an anonymous namespace (libiberty `d_identifier`).
        let anonymous = name.len() >= 10
            && name.starts_with("_GLOBAL_")
            && matches!(name.as_bytes()[8], b'.' | b'_' | b'$')
            && name.as_bytes()[9] == b'N';
        let text: Rc<str> = match anonymous {
            true => "(anonymous namespace)".into(),
            false => name.as_str().into(),
        };
        self.last_name = Some(Rc::clone(&text));
        let mut tags = Vec::new();
        while self.peek() == Some(b'B') {
            self.at += 1;
            let tag = self.number().and_then(|length| self.take(length))?;
            tags.push(String::from_utf8_lossy(tag).into_owned());
        }
        let shown = match tags.is_empty() {
            true => Node::Name(text),
            false => Node::Tagged(Rc::new(Node::Name(text)), tags.into()),
        };
        Some((name, shown))
    }

    /// `S_`, `S<seq-id>_` or a standard abbreviation, after the `S`.
    fn substitution(&mut self) -> Option<Both> {
        // Each abbreviation's expansion as `c++filt` prints it (DMGL_VERBOSE) and the name a
        // constructor or destructor of it takes.
        let (name, expansion, last) = match self.peek()? {
            b'a' => ("allocator", "std::allocator", "allocator"),
            b'b' => ("basic_string", "std::basic_string", "basic_string"),
            b's' => (
                "string",
                "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
                "basic_string",
            ),
            b'i' => (
                "istream",
                "std::basic_istream<char, std::char_traits<char> >",
                "basic_istream",
            ),
            b'o' => (
                "ostream",
                "std::basic_ostream<char, std::char_traits<char> >",
                "basic_ostream",
            ),
            b'd' => (
                "iostream",
                "std::basic_iostream<char, std::char_traits<char> >",
                "basic_iostream",
            ),
            b'_' => {
                self.at += 1;
                return self.substitutions.first().cloned();
            }
            _ => {
                let mut index = 0usize;
                while let Some(byte) = self.peek().filter(|byte| *byte != b'_') {
                    let digit = match byte {
                        b'0'..=b'9' => byte - b'0',
                        b'A'..=b'Z' => byte - b'A' + 10,
                        _ => return None,
                    };
                    index = index.checked_mul(36)?.checked_add(usize::from(digit))?;
                    self.at += 1;
                }
                self.eat(b'_').then_some(())?;
                return self.substitutions.get(index.checked_add(1)?).cloned();
            }
        };
        self.at += 1;
        self.last_name = Some(last.into());
        let ty = Ty::Named {
            name: name.to_owned(),
            class: true,
        };
        Some((ty, Node::name(expansion)))
    }

    /// A function's name: unscoped, `St`-scoped or nested (5.1.2). Local names refuse.
    fn name(&mut self) -> Option<Name> {
        if self.eat(b'N') {
            return self.nested(false).map(|(name, _)| name);
        }
        let std = self.peek() == Some(b'S') && self.text.get(self.at + 1) == Some(&b't');
        if std {
            self.at += 2;
        } else if self.peek() == Some(b'S') {
            // A substitution naming an unscoped template, followed by its arguments.
            self.at += 1;
            let (_, template) = self.substitution()?;
            let args = self.template_args()?;
            return Some(Name {
                object: Object::None,
                shown: Node::template(template, &args),
                template_args: Some(args),
                special: None,
                this: Vec::new(),
            });
        }
        self.eat(b'L');
        let (component, shown) = self.unqualified()?;
        let shown = match std {
            true => Node::scoped(Node::name("std"), shown),
            false => shown,
        };
        let Component::Source(name) = component else {
            // An operator at namespace scope takes its operands as explicit parameters.
            return self.unscoped_template(String::new(), shown);
        };
        self.unscoped_template(name, shown)
    }

    fn unscoped_template(&mut self, name: String, shown: Node) -> Option<Name> {
        let (template_args, shown) = match self.peek() == Some(b'I') {
            true => {
                let template = (Ty::Named { name, class: false }, shown.clone());
                self.substitutions.push(template);
                let args = self.template_args()?;
                let shown = Node::template(shown, &args);
                (Some(args), shown)
            }
            false => (None, shown),
        };
        Some(Name {
            object: Object::None,
            template_args,
            special: None,
            shown,
            this: Vec::new(),
        })
    }

    fn unqualified(&mut self) -> Option<(Component, Node)> {
        let structor = |parser: &mut Self, tilde: &str| {
            let last = parser.last_name.clone();
            parser.unspelled |= last.is_none();
            Node::Name(format!("{tilde}{}", last.unwrap_or_default()).into())
        };
        match self.peek()? {
            b'0'..=b'9' => {
                let (name, shown) = self.source_name()?;
                Some((Component::Source(name), shown))
            }
            b'C' => {
                self.at += 1;
                let variant = self.take(1)?[0];
                matches!(variant, b'1' | b'2' | b'3')
                    .then(|| (Component::Constructor(variant), structor(self, "")))
            }
            b'D' => {
                self.at += 1;
                let variant = self.take(1)?[0];
                matches!(variant, b'0' | b'1' | b'2' | b'4' | b'5')
                    .then(|| (Component::Destructor(variant), structor(self, "~")))
            }
            b'a'..=b'z' => {
                let code = self.take(2)?;
                let code = [code[0], code[1]];
                match &code {
                    // A conversion names its target type; a literal operator, its suffix.
                    b"cv" => {
                        let (ty, shown) = self.ty()?;
                        let shown = Node::Conversion(Rc::new(shown));
                        return Some((Component::Conversion(ty), shown));
                    }
                    b"li" => {
                        let (suffix, _) = self.source_name()?;
                        let shown = Node::Name(format!("operator\"\" {suffix}").into());
                        return Some((Component::Source(String::new()), shown));
                    }
                    [b'v', _] => return None,
                    _ => {}
                }
                let spelling = operator(code);
                self.unspelled |= spelling.is_none();
                let shown = Node::Name(spelling.unwrap_or_default().into());
                Some((Component::Operator(code), shown))
            }
            _ => None,
        }
    }

    /// `N [CV] [ref] <prefix> ... E`. Every prefix is a candidate, and the whole name is one
    /// only as a type (5.1.10). Returns the name and the type it names.
    fn nested(&mut self, as_type: bool) -> Option<(Name, Both)> {
        let mut qualified = false;
        let mut constant = false;
        let mut qualifiers = Vec::new();
        while let Some(byte @ (b'r' | b'V' | b'K' | b'R' | b'O')) = self.peek() {
            qualified = true;
            constant |= byte == b'K';
            qualifiers.push(byte);
            self.at += 1;
        }
        let mut prefixes = self.prefixes()?;
        let current = prefixes.current.take()?;
        if as_type {
            self.candidate(&current, prefixes.fresh);
            self.unspelled |= qualified;
            let unnamed = Name {
                object: Object::None,
                template_args: None,
                special: None,
                shown: current.1.clone(),
                this: Vec::new(),
            };
            return Some((unnamed, current));
        }
        let mut name = prefixes.into_name(qualified, constant, current.1.clone())?;
        name.this = self.this_qualifiers(&qualifiers);
        Some((name, current))
    }

    /// The qualifiers on `this` in the order `c++filt` prints them: the cv-qualifiers last read
    /// first, then the ref-qualifier (libiberty `d_nested_name`). Another order is unspelled.
    fn this_qualifiers(&mut self, read: &[u8]) -> Vec<&'static str> {
        let cv = read
            .iter()
            .take_while(|byte| matches!(byte, b'r' | b'V' | b'K'));
        let mut printed = (cv.collect::<Vec<_>>().into_iter())
            .rev()
            .map(|byte| match byte {
                b'K' => " const",
                b'V' => " volatile",
                _ => " restrict",
            })
            .collect::<Vec<_>>();
        let reference = &read[printed.len()..];
        match reference {
            [] => {}
            [b'R'] => printed.push(" &"),
            [b'O'] => printed.push(" &&"),
            _ => self.unspelled = true,
        }
        printed
    }

    /// The components of a nested name through its `E`.
    fn prefixes(&mut self) -> Option<Prefixes> {
        let mut at = Prefixes::default();
        while !self.eat(b'E') {
            match self.peek()? {
                b'S' if self.text.get(self.at + 1) == Some(&b't') => {
                    self.at += 2;
                    at.std = true;
                }
                b'S' => {
                    self.at += 1;
                    at.restart(self.substitution()?);
                }
                b'T' => {
                    let param = self.template_param()?;
                    self.substitutions.push(param.clone());
                    at.restart(param);
                }
                b'I' => {
                    let (template, shown) = at.current.take()?;
                    self.candidate(&(template.clone(), shown.clone()), at.fresh);
                    let args = self.template_args()?;
                    let shown = Node::template(shown, &args);
                    at.template_args = Some(args);
                    (at.current, at.fresh) = (Some((class(template), shown)), false);
                }
                b'L' => self.at += 1,
                _ => self.component(&mut at)?,
            }
        }
        Some(at)
    }

    /// An unqualified component, named in the scope the components before it name.
    fn component(&mut self, at: &mut Prefixes) -> Option<()> {
        let mut scope = None;
        if let Some(prefix) = at.current.take() {
            self.candidate(&prefix, at.fresh);
            scope = Some(prefix.1);
            at.enclosing = Some(prefix.0);
        }
        let (component, shown) = self.unqualified()?;
        let shown = match (scope, std::mem::take(&mut at.std)) {
            (Some(scope), _) => Node::scoped(scope, shown),
            (None, true) => Node::scoped(Node::name("std"), shown),
            (None, false) => shown,
        };
        let name = match &component {
            Component::Source(name) => name.clone(),
            _ => String::new(),
        };
        (at.current, at.fresh) = (Some((Ty::Named { name, class: false }, shown)), false);
        (at.last, at.template_args) = (Some(component), None);
        Some(())
    }

    /// A prefix becomes a substitution candidate unless it already is one.
    fn candidate(&mut self, ty: &Both, fresh: bool) {
        if !fresh {
            self.substitutions.push(ty.clone());
        }
    }

    fn template_param(&mut self) -> Option<Both> {
        self.at += 1;
        let index = match self.eat(b'_') {
            true => 0,
            false => {
                let index = self.number()?.checked_add(1)?;
                self.eat(b'_').then_some(index)?
            }
        };
        self.template_args.as_ref()?.get(index).cloned()
    }

    /// `I <arg>+ E`; a literal or a pack argument refuses unless it is a type. The arguments
    /// leave the last source name as it was (libiberty `d_template_args_1`).
    fn template_args(&mut self) -> Option<Vec<Both>> {
        if !self.eat(b'I') {
            return None;
        }
        let held = self.last_name.clone();
        let mut args = Vec::new();
        while !self.eat(b'E') {
            match self.peek()? {
                b'L' => args.push(self.literal()?),
                b'X' | b'J' => return None,
                _ => args.push(self.ty()?),
            }
        }
        self.last_name = held;
        Some(args)
    }

    /// A literal argument, `L <type> <value> E`; it is no type a parameter names.
    fn literal(&mut self) -> Option<Both> {
        self.at += 1;
        if self.peek() == Some(b'_') {
            return None;
        }
        let (_, ty) = self.ty()?;
        let start = self.at;
        while self.peek()? != b'E' {
            self.at += 1;
        }
        let value = self.text_from(start);
        self.at += 1;
        Some((Ty::Builtin("int"), Node::Literal(Rc::new(ty), value)))
    }

    /// `F [Y] <type>+ [ref-qualifier] E`, after the `F`.
    fn function(&mut self) -> Option<Both> {
        self.eat(b'Y');
        let mut types = Vec::new();
        let mut reference = None;
        while !self.eat(b'E') {
            // A ref-qualifier sits right before the `E`; elsewhere `R` is a reference.
            let ref_qualifier = self.text.get(self.at + 1) == Some(&b'E');
            let qualifier = self.peek();
            if ref_qualifier && (self.eat(b'R') || self.eat(b'O')) {
                reference = Some(if qualifier == Some(b'R') { " &" } else { " &&" });
            } else {
                types.push(self.ty()?.1);
            }
        }
        let mut types = types.into_iter();
        let result = types.next();
        self.unspelled |= result.is_none();
        let mut parameters = types.collect::<Vec<_>>();
        if parameters == [Node::Builtin("void")] {
            parameters.clear();
        }
        let function = Node::Function(Rc::new(FunctionNode {
            result,
            parameters,
            variadic: false,
        }));
        let shown = match reference {
            Some(qualifier) => Node::RefQualified(qualifier, Rc::new(function)),
            None => function,
        };
        Some((Ty::Function, shown))
    }

    fn ty(&mut self) -> Option<Both> {
        let byte = self.peek()?;
        if let Some((spelling, shown)) = builtin(byte) {
            self.at += 1;
            return Some((Ty::Builtin(spelling), Node::Builtin(shown)));
        }
        let both = match byte {
            b'D' => {
                self.at += 1;
                let (spelling, shown) = match self.take(1)? {
                    b"s" => ("uint16_t", "char16_t"),
                    b"i" => ("uint32_t", "char32_t"),
                    b"u" => ("unsigned char", "char8_t"),
                    b"n" => ("void *", "decltype(nullptr)"),
                    _ => return None,
                };
                return Some((Ty::Builtin(spelling), Node::Builtin(shown)));
            }
            b'P' | b'R' | b'O' => {
                self.at += 1;
                let (ty, shown) = self.ty()?;
                let shown = Rc::new(shown);
                let shown = match byte {
                    b'P' => Node::Pointer(shown),
                    b'R' => Node::Reference(shown),
                    _ => Node::RvalueReference(shown),
                };
                (Ty::Pointer(Box::new(ty)), shown)
            }
            b'K' | b'V' => {
                self.at += 1;
                let qualifier = if byte == b'K' { "const" } else { "volatile" };
                let (ty, shown) = self.ty()?;
                let shown = match byte {
                    b'K' => Node::Const(Rc::new(shown)),
                    _ => Node::Volatile(Rc::new(shown)),
                };
                (Ty::Qualified(qualifier, Box::new(ty)), shown)
            }
            b'r' => {
                // A restrict-qualified type is a candidate (5.1.10) that this does not count.
                self.at += 1;
                self.unspelled = true;
                return self.ty();
            }
            b'F' => {
                self.at += 1;
                self.function()?
            }
            b'A' => {
                self.at += 1;
                let start = self.at;
                self.number();
                let dimension = self.text_from(start);
                self.eat(b'_').then_some(())?;
                let (ty, shown) = self.ty()?;
                (
                    Ty::Pointer(Box::new(ty)),
                    Node::Array(dimension, Rc::new(shown)),
                )
            }
            b'T' => {
                let param = self.template_param()?;
                self.substitutions.push(param.clone());
                // A template template parameter with arguments is not read.
                return (self.peek() != Some(b'I')).then_some(param);
            }
            b'S' if self.text.get(self.at + 1) == Some(&b't') => {
                self.at += 2;
                self.class_name(true)?
            }
            b'S' => {
                self.at += 1;
                let (ty, shown) = self.substitution()?;
                if self.peek() != Some(b'I') {
                    return Some((ty, shown));
                }
                let args = self.template_args()?;
                (class(ty), Node::template(shown, &args))
            }
            b'N' => {
                self.at += 1;
                return self.nested(true).map(|(_, ty)| ty);
            }
            b'0'..=b'9' => self.class_name(false)?,
            _ => return None,
        };
        self.substitutions.push(both.clone());
        Some(both)
    }

    /// An unscoped class or enum name, in `std` where `std`, with its template arguments.
    fn class_name(&mut self, std: bool) -> Option<Both> {
        let (name, shown) = self.source_name()?;
        let shown = match std {
            true => Node::scoped(Node::name("std"), shown),
            false => shown,
        };
        if self.peek() != Some(b'I') {
            return Some((Ty::Named { name, class: false }, shown));
        }
        let template = Ty::Named {
            name: name.clone(),
            class: false,
        };
        self.substitutions.push((template, shown.clone()));
        let args = self.template_args()?;
        Some((
            Ty::Named { name, class: true },
            Node::template(shown, &args),
        ))
    }
}

/// A name with template arguments is a class template's specialisation (or a function's).
fn class(ty: Ty) -> Ty {
    match ty {
        Ty::Named { name, .. } => Ty::Named { name, class: true },
        other => other,
    }
}

/// The builtin types (5.1.5) a C spelling states, as C spells them and as `c++filt` prints
/// them; `__int128`, `__float128`, `long double` and the vendor types refuse.
fn builtin(byte: u8) -> Option<(&'static str, &'static str)> {
    Some(match byte {
        b'v' => ("void", "void"),
        b'w' => ("wchar_t", "wchar_t"),
        b'b' => ("_Bool", "bool"),
        b'c' => ("char", "char"),
        b'a' => ("signed char", "signed char"),
        b'h' => ("unsigned char", "unsigned char"),
        b's' => ("short", "short"),
        b't' => ("unsigned short", "unsigned short"),
        b'i' => ("int", "int"),
        b'j' => ("unsigned int", "unsigned int"),
        b'l' => ("long", "long"),
        b'm' => ("unsigned long", "unsigned long"),
        b'x' => ("long long", "long long"),
        b'y' => ("unsigned long long", "unsigned long long"),
        b'f' => ("float", "float"),
        b'd' => ("double", "double"),
        _ => return None,
    })
}

/// An operator's spelling after `operator` (5.1.3, libiberty `cplus_demangle_operators`): a
/// space before a word, none before a symbol. Expression-only codes are not names.
fn operator(code: [u8; 2]) -> Option<&'static str> {
    Some(match &code {
        b"nw" => "operator new",
        b"na" => "operator new[]",
        b"dl" => "operator delete",
        b"da" => "operator delete[]",
        b"ps" => "operator+",
        b"ng" => "operator-",
        b"ad" => "operator&",
        b"de" => "operator*",
        b"co" => "operator~",
        b"pl" => "operator+",
        b"mi" => "operator-",
        b"ml" => "operator*",
        b"dv" => "operator/",
        b"rm" => "operator%",
        b"an" => "operator&",
        b"or" => "operator|",
        b"eo" => "operator^",
        b"aS" => "operator=",
        b"pL" => "operator+=",
        b"mI" => "operator-=",
        b"mL" => "operator*=",
        b"dV" => "operator/=",
        b"rM" => "operator%=",
        b"aN" => "operator&=",
        b"oR" => "operator|=",
        b"eO" => "operator^=",
        b"ls" => "operator<<",
        b"rs" => "operator>>",
        b"lS" => "operator<<=",
        b"rS" => "operator>>=",
        b"eq" => "operator==",
        b"ne" => "operator!=",
        b"lt" => "operator<",
        b"gt" => "operator>",
        b"le" => "operator<=",
        b"ge" => "operator>=",
        b"ss" => "operator<=>",
        b"nt" => "operator!",
        b"aa" => "operator&&",
        b"oo" => "operator||",
        b"pp" => "operator++",
        b"mm" => "operator--",
        b"cm" => "operator,",
        b"pm" => "operator->*",
        b"pt" => "operator->",
        b"cl" => "operator()",
        b"ix" => "operator[]",
        _ => return None,
    })
}

/// A modifier waiting to be printed around or after what it modifies (libiberty
/// `d_print_mod`): the printer's list of them is a chain through `next`.
#[derive(Clone, Copy)]
enum Mod<'a> {
    Pointer,
    Reference,
    RvalueReference,
    Const,
    Volatile,
    /// A qualifier on `this` or a function type's ref-qualifier: printed after the parameters.
    This(&'static str),
    /// The name a function type is printed around.
    Name(&'a Node),
    Function(&'a FunctionNode),
    Array(&'a str),
}

struct Pending<'a> {
    modifier: Mod<'a>,
    printed: bool,
    next: Option<usize>,
}

/// `c++filt`'s printer (libiberty `d_print_comp`) over the components this reads. A declarator
/// is printed inside out, so each modifier waits on a list until the type it wraps places it.
#[derive(Default)]
struct Printer<'a> {
    out: String,
    pending: Vec<Pending<'a>>,
    failed: bool,
}

impl<'a> Printer<'a> {
    fn last(&self) -> Option<char> {
        self.out.chars().next_back()
    }

    fn push(&mut self, modifier: Mod<'a>, next: Option<usize>) -> usize {
        self.pending.push(Pending {
            modifier,
            printed: false,
            next,
        });
        self.pending.len() - 1
    }

    /// A function's name, with `this`'s qualifiers outermost (libiberty `TYPED_NAME`).
    fn encoding(&mut self, shown: &'a Shown) {
        let mut head = None;
        for qualifier in shown.this.iter().rev() {
            head = Some(self.push(Mod::This(qualifier), head));
        }
        let name = self.push(Mod::Name(&shown.name), head);
        self.function(&shown.function, Some(name));
        for at in (0..=name).rev() {
            if !self.pending[at].printed {
                self.out.push(' ');
                self.modifier(self.pending[at].modifier);
            }
        }
        self.pending.clear();
    }

    fn comp(&mut self, node: &'a Node, head: Option<usize>) {
        match node {
            Node::Name(text) => self.out.push_str(text),
            Node::Builtin(text) => self.out.push_str(text),
            Node::Scoped(scope, name) => {
                self.comp(scope, head);
                self.out.push_str("::");
                self.comp(name, head);
            }
            Node::Template(name, arguments) => {
                self.comp(name, head);
                if self.last() == Some('<') {
                    self.out.push(' ');
                }
                self.out.push('<');
                for (index, argument) in arguments.iter().enumerate() {
                    if index > 0 {
                        self.out.push_str(", ");
                    }
                    self.comp(argument, None);
                }
                // Two `>` in a row would read as a shift.
                if self.last() == Some('>') {
                    self.out.push(' ');
                }
                self.out.push('>');
            }
            Node::Tagged(name, tags) => {
                self.comp(name, head);
                for tag in tags.iter() {
                    self.out.push_str("[abi:");
                    self.out.push_str(tag);
                    self.out.push(']');
                }
            }
            Node::Literal(ty, value) => self.literal(ty, value),
            Node::Pointer(inner) => self.modified(Mod::Pointer, inner, head),
            // A reference to a reference collapses: `&&` under `&&` stays, any other pair is `&`.
            Node::Reference(inner) | Node::RvalueReference(inner) => {
                let rvalue = matches!(node, Node::RvalueReference(_));
                match &**inner {
                    Node::Reference(_) => self.comp(inner, head),
                    Node::RvalueReference(_) if rvalue => self.comp(inner, head),
                    Node::RvalueReference(inside) => self.modified(Mod::Reference, inside, head),
                    _ if rvalue => self.modified(Mod::RvalueReference, inner, head),
                    _ => self.modified(Mod::Reference, inner, head),
                }
            }
            Node::Const(inner) => self.modified(Mod::Const, inner, head),
            Node::Volatile(inner) => self.modified(Mod::Volatile, inner, head),
            Node::RefQualified(qualifier, inner) => {
                self.modified(Mod::This(qualifier), inner, head);
            }
            Node::Function(function) => self.function(function, head),
            Node::Array(dimension, element) => self.array(dimension, element, head),
            Node::Conversion(ty) => {
                self.out.push_str("operator ");
                self.comp(ty, head);
            }
        }
    }

    /// A type under a modifier: the modifier is printed after it unless the type placed it.
    fn modified(&mut self, modifier: Mod<'a>, inner: &'a Node, head: Option<usize>) {
        let at = self.push(modifier, head);
        self.comp(inner, Some(at));
        if !self.pending[at].printed {
            self.modifier(modifier);
        }
        self.pending.truncate(at);
    }

    /// A literal: an integer of a builtin type with its suffix, a boolean as a word, any other
    /// as its type in parentheses before the value (libiberty `DEMANGLE_COMPONENT_LITERAL`).
    fn literal(&mut self, ty: &'a Node, value: &str) {
        let (negative, digits) = match value.strip_prefix('n') {
            Some(digits) => (true, digits),
            None => (false, value),
        };
        let builtin = match ty {
            Node::Builtin(builtin) => Some(*builtin),
            _ => None,
        };
        let suffix = match builtin {
            Some("int") => Some(""),
            Some("unsigned int") => Some("u"),
            Some("long") => Some("l"),
            Some("unsigned long") => Some("ul"),
            Some("long long") => Some("ll"),
            Some("unsigned long long") => Some("ull"),
            _ => None,
        };
        if let Some(suffix) = suffix {
            if negative {
                self.out.push('-');
            }
            self.out.push_str(digits);
            self.out.push_str(suffix);
            return;
        }
        if builtin == Some("bool") && matches!(value, "0" | "1") {
            self.out
                .push_str(if value == "0" { "false" } else { "true" });
            return;
        }
        // A floating literal prints its bytes in brackets and a null pointer's has no value:
        // neither is spelled here.
        self.failed |= digits.is_empty() || matches!(builtin, Some("float" | "double"));
        self.out.push('(');
        self.comp(ty, None);
        self.out.push(')');
        if negative {
            self.out.push('-');
        }
        self.out.push_str(digits);
    }

    /// A function type: its result with the function waiting below it, then the declarator.
    fn function(&mut self, function: &'a FunctionNode, head: Option<usize>) {
        if let Some(result) = &function.result {
            let at = self.push(Mod::Function(function), head);
            self.comp(result, Some(at));
            let printed = self.pending[at].printed;
            self.pending.truncate(at);
            if printed {
                return;
            }
            self.out.push(' ');
        }
        self.function_type(function, head);
    }

    /// libiberty `d_print_function_type`: the waiting modifiers in parentheses where one is a
    /// pointer, reference or qualifier, then the parameters, then the qualifiers on `this`.
    fn function_type(&mut self, function: &'a FunctionNode, mods: Option<usize>) {
        let (mut paren, mut space) = (false, false);
        let mut at = mods;
        while let Some(index) = at {
            let pending = &self.pending[index];
            if pending.printed {
                break;
            }
            match pending.modifier {
                Mod::Pointer | Mod::Reference | Mod::RvalueReference => paren = true,
                Mod::Const | Mod::Volatile => (paren, space) = (true, true),
                _ => {}
            }
            if paren {
                break;
            }
            at = pending.next;
        }
        if paren {
            space |= !matches!(self.last(), Some('(' | '*'));
            if space && self.last() != Some(' ') {
                self.out.push(' ');
            }
            self.out.push('(');
        }
        self.mod_list(mods, false);
        if paren {
            self.out.push(')');
        }
        self.out.push('(');
        for (index, parameter) in function.parameters.iter().enumerate() {
            if index > 0 {
                self.out.push_str(", ");
            }
            self.comp(parameter, None);
        }
        if function.variadic {
            if !function.parameters.is_empty() {
                self.out.push_str(", ");
            }
            self.out.push_str("...");
        }
        self.out.push(')');
        self.mod_list(mods, true);
    }

    /// libiberty `d_print_mod_list`: each waiting modifier once, a qualifier on `this` only
    /// after the parameters (`suffix`), a function or array around the rest.
    fn mod_list(&mut self, mods: Option<usize>, suffix: bool) {
        let mut at = mods;
        while let Some(index) = at {
            let Pending {
                modifier,
                printed,
                next,
            } = self.pending[index];
            at = next;
            if printed || (!suffix && matches!(modifier, Mod::This(_))) {
                continue;
            }
            self.pending[index].printed = true;
            match modifier {
                Mod::Function(function) => return self.function_type(function, next),
                Mod::Array(dimension) => return self.array_type(dimension, next),
                modifier => self.modifier(modifier),
            }
        }
    }

    fn modifier(&mut self, modifier: Mod<'a>) {
        match modifier {
            Mod::Pointer => self.out.push('*'),
            Mod::Reference => self.out.push('&'),
            Mod::RvalueReference => self.out.push_str("&&"),
            Mod::Const => self.out.push_str(" const"),
            Mod::Volatile => self.out.push_str(" volatile"),
            Mod::This(qualifier) => self.out.push_str(qualifier),
            Mod::Name(name) => self.comp(name, None),
            // Each is placed by the type it wraps.
            Mod::Function(_) | Mod::Array(_) => self.failed = true,
        }
    }

    /// An array type: the element with the array waiting below it, then the declarator. A
    /// cv-qualifier on the array is printed as its element's (libiberty `ARRAY_TYPE`).
    fn array(&mut self, dimension: &'a str, element: &'a Node, head: Option<usize>) {
        let at = self.push(Mod::Array(dimension), head);
        let (mut top, mut moved) = (at, Vec::new());
        let mut walk = head;
        while let Some(index) = walk {
            let Pending {
                modifier,
                printed,
                next,
            } = self.pending[index];
            if !matches!(modifier, Mod::Const | Mod::Volatile) {
                break;
            }
            if !printed {
                self.pending[index].printed = true;
                top = self.push(modifier, Some(top));
                moved.push(modifier);
            }
            walk = next;
        }
        self.comp(element, Some(top));
        let printed = self.pending[at].printed;
        self.pending.truncate(at);
        if printed {
            return;
        }
        for modifier in moved.into_iter().rev() {
            self.modifier(modifier);
        }
        self.array_type(dimension, head);
    }

    /// libiberty `d_print_array_type`.
    fn array_type(&mut self, dimension: &'a str, mods: Option<usize>) {
        let mut space = true;
        if mods.is_some() {
            let mut paren = false;
            let mut at = mods;
            while let Some(index) = at {
                let pending = &self.pending[index];
                if !pending.printed {
                    match pending.modifier {
                        Mod::Array(_) => space = false,
                        _ => (paren, space) = (true, true),
                    }
                    break;
                }
                at = pending.next;
            }
            if paren {
                self.out.push_str(" (");
            }
            self.mod_list(mods, false);
            if paren {
                self.out.push(')');
            }
        }
        if space {
            self.out.push(' ');
        }
        self.out.push('[');
        self.out.push_str(dimension);
        self.out.push(']');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stated(name: &str) -> (Object, Vec<String>) {
        let mangled = parse(name).unwrap_or_else(|| panic!("{name}"));
        (mangled.object, mangled.parameters)
    }

    fn strings(spellings: &[&str]) -> Vec<String> {
        spellings
            .iter()
            .map(|&spelling| spelling.to_owned())
            .collect()
    }

    /// Each parameter list as c++filt prints it, with references read as their pointers.
    #[test]
    fn a_mangled_name_states_its_parameters() {
        let ostream_insert =
            "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l";
        assert_eq!(
            stated(ostream_insert),
            (
                Object::None,
                strings(&["basic_ostream *", "const char *", "long"])
            )
        );
        assert_eq!(
            stated("_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_"),
            (Object::None, strings(&["basic_ostream *"]))
        );
        assert_eq!(
            stated("_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base"),
            (Object::None, strings(&["_Rb_tree_node_base *"]))
        );
        let insert = "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_";
        let node = "_Rb_tree_node_base *";
        assert_eq!(stated(insert).1, strings(&["_Bool", node, node, node]));
        assert_eq!(stated("_Z3fooiz").1, strings(&["int"]));
        assert!(parse("_Z3fooiz").expect("foo").variadic);
        assert_eq!(stated("_Z3barv"), (Object::None, Vec::new()));
    }

    /// A constructor, a destructor, a const member and a class's operator take `this`.
    #[test]
    fn a_member_the_name_proves_takes_its_object_first() {
        let this = |spelling: &str| Object::This(spelling.to_owned());
        assert_eq!(
            stated("_ZNSt8ios_base4InitC1Ev"),
            (this("Init *"), Vec::new())
        );
        assert_eq!(stated("_ZNSt6localeD1Ev"), (this("locale *"), Vec::new()));
        assert_eq!(
            stated("_ZNKSt5ctypeIcE13_M_widen_initEv"),
            (this("const ctype *"), Vec::new())
        );
        assert_eq!(stated("_ZNSolsEi"), (this("ostream *"), strings(&["int"])));
        let create = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm";
        assert_eq!(
            stated(create),
            (
                Object::Unstated("basic_string *".to_owned()),
                strings(&["unsigned long *", "unsigned long"])
            )
        );
        let assign = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_assignERKS4_";
        assert_eq!(stated(assign).1, strings(&["const basic_string *"]));
        // A template member's first type is its result, not a parameter.
        assert_eq!(
            stated("_ZNSo9_M_insertImEERSoT_"),
            (
                Object::Unstated("ostream *".to_owned()),
                strings(&["unsigned long"])
            )
        );
        let svd = "_ZN6NEWMAT3SVDERKNS_6MatrixERNS_14DiagonalMatrixERS0_S5_bb";
        let matrix = "Matrix *";
        let expected = [
            "const Matrix *",
            "DiagonalMatrix *",
            matrix,
            matrix,
            "_Bool",
            "_Bool",
        ];
        assert_eq!(stated(svd).1, strings(&expected));
    }

    /// A namespace or class the name leaves open states no object: neither is guessed.
    #[test]
    fn an_open_scope_leaves_the_object_unstated() {
        assert!(matches!(
            stated("_ZNSt3_V216generic_categoryEv").0,
            Object::Unstated(_)
        ));
        assert!(matches!(
            stated("_ZNSt8ios_base6xallocEv").0,
            Object::Unstated(_)
        ));
        // `operator()` may be static from C++23, and a namespace's operator<< takes two operands.
        assert!(matches!(
            stated("_ZN6NEWMAT6MatrixclEii").0,
            Object::Unstated(_)
        ));
        assert!(matches!(
            stated("_ZN2cvlsERSoRKNS_3MatE").0,
            Object::Unstated(_)
        ));
    }

    /// A result the name does not encode may pass a hidden pointer first, and a base-object
    /// structor may take a VTT: neither states every leading location (PR #349 review).
    #[test]
    fn a_name_states_its_leading_locations_only_where_it_encodes_them() {
        let passing = |name: &str| parse(name).unwrap_or_else(|| panic!("{name}")).passing;
        assert_eq!(passing("_Z3fooi"), Passing::HiddenResultUnstated);
        assert_eq!(passing("_ZNSo5flushEv"), Passing::HiddenResultUnstated);
        assert_eq!(passing("_ZN1BC2Ei"), Passing::VttUnstated);
        assert_eq!(passing("_ZN1BD2Ev"), Passing::VttUnstated);
        for name in [
            "_ZN1BC1Ei",
            "_ZN1BD1Ev",
            "_ZN1BD0Ev",
            "_ZNSo9_M_insertImEERSoT_",
        ] {
            assert_eq!(passing(name), Passing::Stated, "{name}");
        }
        // A template returning a class by value may return it in memory.
        assert_eq!(passing("_Z4makeIiE3Bigv"), Passing::HiddenResultUnstated);
        assert_eq!(passing("_ZNK1AcviEv"), Passing::Stated);
    }

    /// Names from 0pack's `.symtab`, each spelled byte for byte as GNU `c++filt` 2.42 prints it.
    #[test]
    fn a_name_is_spelled_as_cxxfilt_prints_it() {
        let spelled = |name: &str| parse(name).and_then(|mangled| mangled.spelled());
        for (name, expected) in [
            (
                "_ZN2el4base9VRegistry7allowedEtPKc",
                "el::base::VRegistry::allowed(unsigned short, char const*)",
            ),
            ("_ZN4LIEF9corruptedD1Ev", "LIEF::corrupted::~corrupted()"),
            (
                "_Z12print_vectorRSt6vectorIhSaIhEE",
                "print_vector(std::vector<unsigned char, std::allocator<unsigned char> >&)",
            ),
            (
                "_Z13random_stringB5cxx11m",
                "random_string[abi:cxx11](unsigned long)",
            ),
            (
                "_ZN4LIEF3ELFli8_sectionEPKc.cold.149",
                "LIEF::ELF::operator\"\" _section(char const*) [clone .cold.149]",
            ),
            (
                "_ZNSt12experimental10filesystem2v17__cxx114pathC1IA8_cS3_EERKT_",
                "std::experimental::filesystem::v1::__cxx11::path::path<char [8], \
                 std::experimental::filesystem::v1::__cxx11::path>(char const (&) [8])",
            ),
            (
                "_ZN3fmt2v58internal22handle_float_type_specIcRNS0_18float_spec_handlerIcEEEEvT_OT0_",
                "void fmt::v5::internal::handle_float_type_spec<char, \
                 fmt::v5::float_spec_handler<char>&>(char, fmt::v5::float_spec_handler<char>&)",
            ),
        ] {
            assert_eq!(spelled(name).as_deref(), Some(expected), "{name}");
        }
    }

    /// A pack, a `long double` and a clone suffix outside the grammar: `c++filt` prints the
    /// first two, and this leaves each mangled rather than spell a production it does not read.
    #[test]
    fn a_production_this_does_not_spell_leaves_the_name_mangled() {
        for name in [
            "_ZN10Obfuscator3ELF6Loader6appendIJEEEvNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEDpRKT_",
            "_ZN3fmt2v58internal11char_traitsIcE12format_floatIeEEiPcmPKciT_",
            "_Z3foov.Cold",
        ] {
            assert_eq!(
                parse(name).and_then(|mangled| mangled.spelled()),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn what_this_does_not_read_refuses_the_name() {
        for name in [
            "main",
            "_ZTV7Derived",
            "_ZZ4mainE5count",
            "_Z1fIJiiEEvDpT_",
            "_Z1fu6vendor",
        ] {
            assert_eq!(parse(name), None, "{name}");
        }
    }
}
