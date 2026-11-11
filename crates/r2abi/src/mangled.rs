//! The parameters an Itanium C++ ABI mangled name states (5.1); its rows return `Unproven`, and
//! a name this does not parse is refused whole (doc/adr-call-boundary.md, S13 as built).

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
}

/// The parameters `name` states, or `None` where it is not a function's mangled name this reads.
/// O(name length), with substitutions looked up by index.
pub fn parse(name: &str) -> Option<Mangled> {
    let name = name.split(['.', '@']).next()?;
    let body = name.strip_prefix("_Z")?;
    let mut parser = Parser {
        text: body.as_bytes(),
        at: 0,
        substitutions: Vec::new(),
        template_args: None,
    };
    let function = parser.name()?;
    parser.template_args.clone_from(&function.template_args);
    // A template function's first type is its result (5.1.3); a conversion names its own.
    let result = match (&function.special, function.template_args.is_some()) {
        (Some(Special::Conversion(ty)), _) => Some(ty.clone()),
        (None, true) => Some(parser.ty()?),
        _ => None,
    };
    let passing = match (&function.special, result) {
        (Some(Special::Structor(b'1' | b'0')), _) => Passing::Stated,
        (Some(Special::Structor(_)), _) => Passing::VttUnstated,
        (_, Some(result)) if result.in_registers() => Passing::Stated,
        _ => Passing::HiddenResultUnstated,
    };
    let (mut parameters, mut variadic, mut none) = (Vec::new(), false, false);
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
            _ => parameters.push(parser.ty()?.spell()?),
        }
    }
    (variadic || none || !parameters.is_empty()).then_some(Mangled {
        object: function.object,
        passing,
        parameters,
        variadic,
    })
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

/// A function's name as it decides the object parameter and the template arguments.
struct Name {
    object: Object,
    template_args: Option<Vec<Ty>>,
    /// A constructor, destructor or conversion, whose template arguments encode no result.
    special: Option<Special>,
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
    current: Option<Ty>,
    /// `current` is a substitution, already a candidate.
    fresh: bool,
    /// The scope the last component is named in.
    enclosing: Option<Ty>,
    last: Option<Component>,
    template_args: Option<Vec<Ty>>,
}

impl Prefixes {
    /// A substitution or template parameter names everything so far afresh.
    fn restart(&mut self, ty: Ty) {
        (self.current, self.fresh) = (Some(ty), true);
        (self.last, self.template_args) = (None, None);
    }

    /// The function the components name, its `this` cv- or ref-qualified where `qualified`.
    fn into_name(self, qualified: bool, constant: bool) -> Option<Name> {
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
        })
    }
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    /// Every substitution candidate in order (5.1.10): `S_` is the first, `S0_` the second.
    substitutions: Vec<Ty>,
    /// The function's own template arguments, which `T_` names.
    template_args: Option<Vec<Ty>>,
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

    fn source_name(&mut self) -> Option<String> {
        let length = self.number()?;
        let name = std::str::from_utf8(self.take(length)?).ok()?.to_owned();
        // An ABI tag (`B5cxx11`) names no new entity (5.1.2).
        while self.peek() == Some(b'B') {
            self.at += 1;
            self.number().and_then(|length| self.take(length))?;
        }
        Some(name)
    }

    /// `S_`, `S<seq-id>_` or a standard abbreviation, after the `S`.
    fn substitution(&mut self) -> Option<Ty> {
        let abbreviation = |name: &str| Ty::Named {
            name: name.to_owned(),
            class: true,
        };
        let ty = match self.peek()? {
            b'a' => abbreviation("allocator"),
            b'b' => abbreviation("basic_string"),
            b's' => abbreviation("string"),
            b'i' => abbreviation("istream"),
            b'o' => abbreviation("ostream"),
            b'd' => abbreviation("iostream"),
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
        Some(ty)
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
            self.substitution()?;
            let args = self.template_args()?;
            return Some(Name {
                object: Object::None,
                template_args: Some(args),
                special: None,
            });
        }
        self.eat(b'L');
        let Component::Source(name) = self.unqualified()? else {
            // An operator at namespace scope takes its operands as explicit parameters.
            return self.unscoped_template(String::new());
        };
        self.unscoped_template(name)
    }

    fn unscoped_template(&mut self, name: String) -> Option<Name> {
        let template_args = match self.peek() == Some(b'I') {
            true => {
                self.substitutions.push(Ty::Named { name, class: false });
                Some(self.template_args()?)
            }
            false => None,
        };
        Some(Name {
            object: Object::None,
            template_args,
            special: None,
        })
    }

    fn unqualified(&mut self) -> Option<Component> {
        match self.peek()? {
            b'0'..=b'9' => Some(Component::Source(self.source_name()?)),
            b'C' => {
                self.at += 1;
                let variant = self.take(1)?[0];
                matches!(variant, b'1' | b'2' | b'3').then_some(Component::Constructor(variant))
            }
            b'D' => {
                self.at += 1;
                let variant = self.take(1)?[0];
                matches!(variant, b'0' | b'1' | b'2' | b'4' | b'5')
                    .then_some(Component::Destructor(variant))
            }
            b'a'..=b'z' => {
                let code = self.take(2)?;
                let code = [code[0], code[1]];
                match &code {
                    // A conversion names its target type; a literal operator, its suffix.
                    b"cv" => return Some(Component::Conversion(self.ty()?)),
                    b"li" => {
                        self.source_name()?;
                        return Some(Component::Source(String::new()));
                    }
                    [b'v', _] => return None,
                    _ => {}
                }
                Some(Component::Operator(code))
            }
            _ => None,
        }
    }

    /// `N [CV] [ref] <prefix> ... E`. Every prefix is a candidate, and the whole name is one
    /// only as a type (5.1.10). Returns the name and the type it names.
    fn nested(&mut self, as_type: bool) -> Option<(Name, Ty)> {
        let mut qualified = false;
        let mut constant = false;
        while let Some(byte @ (b'r' | b'V' | b'K' | b'R' | b'O')) = self.peek() {
            qualified = true;
            constant |= byte == b'K';
            self.at += 1;
        }
        let mut prefixes = self.prefixes()?;
        let current = prefixes.current.take()?;
        if as_type {
            self.candidate(&current, prefixes.fresh);
            let unnamed = Name {
                object: Object::None,
                template_args: None,
                special: None,
            };
            return Some((unnamed, current));
        }
        Some((prefixes.into_name(qualified, constant)?, current))
    }

    /// The components of a nested name through its `E`.
    fn prefixes(&mut self) -> Option<Prefixes> {
        let mut at = Prefixes::default();
        while !self.eat(b'E') {
            match self.peek()? {
                b'S' if self.text.get(self.at + 1) == Some(&b't') => self.at += 2,
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
                    let template = at.current.take()?;
                    self.candidate(&template, at.fresh);
                    at.template_args = Some(self.template_args()?);
                    (at.current, at.fresh) = (Some(class(template)), false);
                }
                b'L' => self.at += 1,
                _ => self.component(&mut at)?,
            }
        }
        Some(at)
    }

    /// An unqualified component, named in the scope the components before it name.
    fn component(&mut self, at: &mut Prefixes) -> Option<()> {
        if let Some(prefix) = at.current.take() {
            self.candidate(&prefix, at.fresh);
            at.enclosing = Some(prefix);
        }
        let component = self.unqualified()?;
        let name = match &component {
            Component::Source(name) => name.clone(),
            _ => String::new(),
        };
        (at.current, at.fresh) = (Some(Ty::Named { name, class: false }), false);
        (at.last, at.template_args) = (Some(component), None);
        Some(())
    }

    /// A prefix becomes a substitution candidate unless it already is one.
    fn candidate(&mut self, ty: &Ty, fresh: bool) {
        if !fresh {
            self.substitutions.push(ty.clone());
        }
    }

    fn template_param(&mut self) -> Option<Ty> {
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

    /// `I <arg>+ E`; a literal or a pack argument refuses unless it is a type.
    fn template_args(&mut self) -> Option<Vec<Ty>> {
        if !self.eat(b'I') {
            return None;
        }
        let mut args = Vec::new();
        while !self.eat(b'E') {
            match self.peek()? {
                b'L' => args.push(self.literal()?),
                b'X' | b'J' => return None,
                _ => args.push(self.ty()?),
            }
        }
        Some(args)
    }

    /// A literal argument, `L <type> <value> E`; it is no type a parameter names.
    fn literal(&mut self) -> Option<Ty> {
        self.at += 1;
        if self.peek() == Some(b'_') {
            return None;
        }
        self.ty()?;
        while self.peek()? != b'E' {
            self.at += 1;
        }
        self.at += 1;
        Some(Ty::Builtin("int"))
    }

    /// `F [Y] <type>+ [ref-qualifier] E`, after the `F`.
    fn function(&mut self) -> Option<Ty> {
        self.eat(b'Y');
        while !self.eat(b'E') {
            // A ref-qualifier sits right before the `E`; elsewhere `R` is a reference.
            let ref_qualifier = self.text.get(self.at + 1) == Some(&b'E');
            if !(ref_qualifier && (self.eat(b'R') || self.eat(b'O'))) {
                self.ty()?;
            }
        }
        Some(Ty::Function)
    }

    fn ty(&mut self) -> Option<Ty> {
        let byte = self.peek()?;
        if let Some(spelling) = builtin(byte) {
            self.at += 1;
            return Some(Ty::Builtin(spelling));
        }
        let ty = match byte {
            b'D' => {
                self.at += 1;
                let spelling = match self.take(1)? {
                    b"s" => "uint16_t",
                    b"i" => "uint32_t",
                    b"u" => "unsigned char",
                    b"n" => "void *",
                    _ => return None,
                };
                return Some(Ty::Builtin(spelling));
            }
            b'P' | b'R' | b'O' => {
                self.at += 1;
                Ty::Pointer(Box::new(self.ty()?))
            }
            b'K' | b'V' => {
                self.at += 1;
                let qualifier = if byte == b'K' { "const" } else { "volatile" };
                Ty::Qualified(qualifier, Box::new(self.ty()?))
            }
            b'r' => {
                self.at += 1;
                return self.ty();
            }
            b'F' => {
                self.at += 1;
                self.function()?
            }
            b'A' => {
                self.at += 1;
                self.number();
                self.eat(b'_').then_some(())?;
                Ty::Pointer(Box::new(self.ty()?))
            }
            b'T' => {
                let param = self.template_param()?;
                self.substitutions.push(param.clone());
                // A template template parameter with arguments is not read.
                return (self.peek() != Some(b'I')).then_some(param);
            }
            b'S' if self.text.get(self.at + 1) == Some(&b't') => {
                self.at += 2;
                self.class_name()?
            }
            b'S' => {
                self.at += 1;
                let ty = self.substitution()?;
                if self.peek() != Some(b'I') {
                    return Some(ty);
                }
                self.template_args()?;
                class(ty)
            }
            b'N' => {
                self.at += 1;
                return self.nested(true).map(|(_, ty)| ty);
            }
            b'0'..=b'9' => self.class_name()?,
            _ => return None,
        };
        self.substitutions.push(ty.clone());
        Some(ty)
    }

    /// An unscoped class or enum name, with its template arguments.
    fn class_name(&mut self) -> Option<Ty> {
        let name = self.source_name()?;
        if self.peek() != Some(b'I') {
            return Some(Ty::Named { name, class: false });
        }
        self.substitutions.push(Ty::Named {
            name: name.clone(),
            class: false,
        });
        self.template_args()?;
        Some(Ty::Named { name, class: true })
    }
}

/// A name with template arguments is a class template's specialisation (or a function's).
fn class(ty: Ty) -> Ty {
    match ty {
        Ty::Named { name, .. } => Ty::Named { name, class: true },
        other => other,
    }
}

/// The builtin types (5.1.5) a C spelling states; `__int128`, `__float128`, `long double` and the
/// vendor types refuse.
fn builtin(byte: u8) -> Option<&'static str> {
    Some(match byte {
        b'v' => "void",
        b'w' => "wchar_t",
        b'b' => "_Bool",
        b'c' => "char",
        b'a' => "signed char",
        b'h' => "unsigned char",
        b's' => "short",
        b't' => "unsigned short",
        b'i' => "int",
        b'j' => "unsigned int",
        b'l' => "long",
        b'm' => "unsigned long",
        b'x' => "long long",
        b'y' => "unsigned long long",
        b'f' => "float",
        b'd' => "double",
        _ => return None,
    })
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
