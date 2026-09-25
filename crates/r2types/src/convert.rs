use crate::model::{Signedness, Type, TypeArena, TypeId};

/// What every bit-vector struct tag starts with.
const BIT_VECTOR_TAG_PREFIX: &str = "r2sleigh_bits_";

/// The struct tag a bit vector of `bits` is declared at: the one spelling of
/// it, which the type spellings here print and parse and the renderer defines.
pub fn bit_vector_tag(bits: u32) -> String {
    format!("{BIT_VECTOR_TAG_PREFIX}{bits}")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum CTypeLike {
    Void,
    Bool,
    Int {
        bits: u32,
        signedness: Signedness,
    },
    Float(u32),
    /// An exact machine bitvector wider than, or not expressible in, C's native
    /// integer domain, declared at the struct tag [`bit_vector_tag`] names.
    ///
    /// Distinct from `Int` on purpose: keeping it apart is what stops ordinary
    /// C arithmetic and casts being emitted for a value the language has no
    /// scalar for. The renderer owns the struct's layout and the helpers that
    /// operate on it (`r2dec::bitvector`).
    BitVector(u32),
    Pointer(Box<CTypeLike>),
    Array(Box<CTypeLike>, Option<usize>),
    Struct(String),
    Union(String),
    Enum(String),
    /// A name the source gave a type, with what the name stands for.
    ///
    /// The name is presentation and the target is the type: width, signedness
    /// and indirection all come from `ty`, so a named type is not a hole in
    /// the width machinery. It was one -- the variant carried a name alone,
    /// every consumer that needed a width re-parsed the text, that only worked
    /// for standard spellings, and `admit_declaration_type` replaced every
    /// other named type with the machine word. A name the capture could not
    /// resolve carries `Unknown`, which is exactly what the variant used to
    /// mean everywhere.
    Typedef {
        name: String,
        ty: Box<CTypeLike>,
    },
    /// A function type, with the signature it was recovered with.
    ///
    /// This carried no signature until the two type models were folded
    /// together: `r2dec`'s `CType::Function` had a return type and parameters,
    /// and every trip through here erased them.
    Function {
        ret: Box<CTypeLike>,
        /// A boxed slice rather than a growable list: nothing appends to a
        /// recovered signature after it is made, and the capacity word made
        /// every type in the tree eight bytes wider -- a type sits inside
        /// every cast and every declaration a rendering emits.
        params: Box<[CTypeLike]>,
    },
    /// A `const`-qualified pointee: what `const char *` points at.
    ///
    /// Only a pointee carries the qualifier. A top-level qualifier is not part
    /// of a prototype's type, but a pointee's is: a declaration of `printf`
    /// that spells `char *` where the library says `const char *` is a
    /// different type to the compiler, and it refuses the redeclaration.
    Const(Box<CTypeLike>),
    Unknown,
}

impl std::fmt::Display for CTypeLike {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&render_c_type_like(self))
    }
}

impl CTypeLike {
    /// A signed integer of the given width.
    pub const fn int(bits: u32) -> Self {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Signed,
        }
    }

    /// An unsigned integer of the given width.
    pub const fn uint(bits: u32) -> Self {
        CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        }
    }

    /// A signed 8-bit integer.
    pub const fn i8() -> Self {
        Self::int(8)
    }

    /// A signed 16-bit integer.
    pub const fn i16() -> Self {
        Self::int(16)
    }

    /// A signed 32-bit integer.
    pub const fn i32() -> Self {
        Self::int(32)
    }

    /// A signed 64-bit integer.
    pub const fn i64() -> Self {
        Self::int(64)
    }

    /// A unsigned 8-bit integer.
    pub const fn u8() -> Self {
        Self::uint(8)
    }

    /// A unsigned 16-bit integer.
    pub const fn u16() -> Self {
        Self::uint(16)
    }

    /// A unsigned 32-bit integer.
    pub const fn u32() -> Self {
        Self::uint(32)
    }

    /// A unsigned 64-bit integer.
    pub const fn u64() -> Self {
        Self::uint(64)
    }

    /// Whether C has an integer exactly `bits` wide: `uint8_t` through
    /// `uint64_t`, or `__uint128_t`.
    ///
    /// The one statement of which machine widths are C integers. The supported
    /// compiler contract has scalar integer spellings through 128 bits; any
    /// other width is a [`CTypeLike::BitVector`] carrier rather than an
    /// invented name such as `uint256_t`.
    pub const fn is_integer_width(bits: u32) -> bool {
        matches!(bits, 8 | 16 | 32 | 64 | 128)
    }

    /// Exact unsigned machine storage of the given width.
    ///
    /// An unsigned integer where [`Self::is_integer_width`] says C has one,
    /// and otherwise a [`CTypeLike::BitVector`] carrier of the whole width,
    /// whose representation the renderer defines in each rendering that
    /// declares one.
    pub const fn machine_bits(bits: u32) -> Self {
        if Self::is_integer_width(bits) {
            Self::uint(bits)
        } else {
            CTypeLike::BitVector(bits)
        }
    }

    /// A pointer to the given type.
    pub fn ptr(inner: CTypeLike) -> Self {
        CTypeLike::Pointer(Box::new(inner))
    }

    /// A pointer to void.
    pub fn void_ptr() -> Self {
        Self::ptr(CTypeLike::Void)
    }

    /// The width in bits, where the type has one.
    /// A name whose target the capture did not resolve.
    pub fn typedef(name: impl Into<String>) -> Self {
        CTypeLike::Typedef {
            name: name.into(),
            ty: Box::new(CTypeLike::Unknown),
        }
    }

    /// A name over the type it stands for.
    pub fn named(name: impl Into<String>, ty: CTypeLike) -> Self {
        CTypeLike::Typedef {
            name: name.into(),
            ty: Box::new(ty),
        }
    }

    /// This type with every name resolved away, which is the type it is.
    pub fn unaliased(&self) -> &CTypeLike {
        match self {
            CTypeLike::Typedef { ty, .. } if !matches!(ty.as_ref(), CTypeLike::Unknown) => {
                ty.unaliased()
            }
            CTypeLike::Const(ty) => ty.unaliased(),
            other => other,
        }
    }

    /// This type without its qualifier, which is what it is a type of.
    pub fn unqualified(&self) -> &CTypeLike {
        match self {
            CTypeLike::Const(ty) => ty.unqualified(),
            other => other,
        }
    }

    /// The aggregate tag this type is, through any number of names.
    ///
    /// A name is transparent: `bz_stream` naming `struct type_0x5e55` is that
    /// struct. Ten structural tests had to learn this one regression at a
    /// time, so the questions they ask live here and look through names by
    /// construction rather than by each caller remembering to.
    pub fn aggregate_tag(&self) -> Option<&str> {
        match self.unaliased() {
            CTypeLike::Struct(name) | CTypeLike::Union(name) => Some(name),
            _ => None,
        }
    }

    /// Whether this is a struct or union, through any names.
    pub fn is_aggregate(&self) -> bool {
        self.aggregate_tag().is_some()
    }

    /// Whether this is a union rather than a struct, through any names.
    pub fn is_union(&self) -> bool {
        matches!(self.unaliased(), CTypeLike::Union(_))
    }

    /// Whether this is an array, through any names.
    pub fn is_array(&self) -> bool {
        matches!(self.unaliased(), CTypeLike::Array(..))
    }

    /// What `name[i]` reaches: a pointer's target or an array's element.
    ///
    /// The two are one question at a subscript, because an array decays to a
    /// pointer to its element exactly where it is subscripted.
    pub fn subscript_element(&self) -> Option<&CTypeLike> {
        match self.unaliased() {
            CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => Some(inner),
            _ => None,
        }
    }

    /// Whether `name[i]` is legal on this type, through any names.
    ///
    /// `Unknown` is admitted: nothing has said the value is not a pointer, and
    /// refusing on no evidence is not a claim this model makes.
    pub fn may_be_subscripted(&self) -> bool {
        self.subscript_element().is_some() || matches!(self.unaliased(), CTypeLike::Unknown)
    }

    pub fn bits(&self, ptr_bits: u32) -> Option<u32> {
        match self {
            CTypeLike::Bool => Some(1),
            CTypeLike::Int { bits, .. } | CTypeLike::BitVector(bits) | CTypeLike::Float(bits) => {
                Some(*bits)
            }
            CTypeLike::Pointer(_) => Some(ptr_bits),
            // A name stands for its target, so it is as wide as the target is.
            CTypeLike::Typedef { ty, .. } | CTypeLike::Const(ty) => ty.bits(ptr_bits),
            _ => None,
        }
    }

    /// Whether this is a signed integer.
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            CTypeLike::Int {
                signedness: Signedness::Signed,
                ..
            }
        )
    }

    /// Whether this is an integer, boolean included.
    pub fn is_integer(&self) -> bool {
        matches!(self, CTypeLike::Int { .. } | CTypeLike::Bool)
    }

    /// Whether this is a pointer to anything.
    pub fn is_pointer(&self) -> bool {
        matches!(self, CTypeLike::Pointer(_))
    }

    /// Whether this is `void *`.
    pub fn is_void_pointer(&self) -> bool {
        matches!(self, CTypeLike::Pointer(inner) if matches!(**inner, CTypeLike::Void))
    }
}

pub fn to_c_type_like(arena: &TypeArena, ty: TypeId) -> CTypeLike {
    match arena.get(ty) {
        Type::Top | Type::Bottom => CTypeLike::Unknown,
        Type::Bool => CTypeLike::Bool,
        Type::Int { bits, signedness } => CTypeLike::Int {
            bits: *bits,
            signedness: *signedness,
        },
        Type::Float { bits } => CTypeLike::Float(*bits),
        Type::Ptr(inner) => CTypeLike::Pointer(Box::new(to_c_type_like(arena, *inner))),
        Type::Array { elem, len, .. } => {
            CTypeLike::Array(Box::new(to_c_type_like(arena, *elem)), *len)
        }
        Type::Struct(shape) => {
            CTypeLike::Struct(shape.name.clone().unwrap_or_else(|| "anon".to_string()))
        }
        Type::Function { params, ret, .. } => CTypeLike::Function {
            ret: Box::new(to_c_type_like(arena, *ret)),
            params: params
                .iter()
                .map(|param| to_c_type_like(arena, *param))
                .collect(),
        },
        Type::UnknownAlias(name) if name == "void" => CTypeLike::Void,
        Type::UnknownAlias(name) if name.starts_with("struct ") => {
            CTypeLike::Struct(name.trim_start_matches("struct ").to_string())
        }
        Type::UnknownAlias(name) if name.starts_with("union ") => {
            CTypeLike::Union(name.trim_start_matches("union ").to_string())
        }
        Type::UnknownAlias(name) if name.starts_with("enum ") => {
            CTypeLike::Enum(name.trim_start_matches("enum ").to_string())
        }
        Type::UnknownAlias(name) => CTypeLike::typedef(name.clone()),
    }
}

pub fn render_c_type_like(ty: &CTypeLike) -> String {
    match ty {
        CTypeLike::Void => "void".to_string(),
        // `_Bool`, not `bool`: this spelling goes into the C the decompiler
        // emits, and that translation unit carries no `#include <stdbool.h>`.
        // `bool` is a macro from that header, while `_Bool` is a keyword every
        // C99 and later compiler accepts on its own. The parser above reads
        // both spellings back, so nothing that consumes this text loses.
        CTypeLike::Bool => "_Bool".to_string(),
        CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Signed,
        } => "int8_t".to_string(),
        CTypeLike::Int {
            bits: 16,
            signedness: Signedness::Signed,
        } => "int16_t".to_string(),
        CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Signed,
        } => "int32_t".to_string(),
        CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Signed,
        } => "int64_t".to_string(),
        CTypeLike::Int {
            bits: 128,
            signedness: Signedness::Signed | Signedness::Unknown,
        } => "__int128_t".to_string(),
        CTypeLike::Int {
            bits,
            signedness: Signedness::Signed | Signedness::Unknown,
        } => format!("int{bits}_t"),
        CTypeLike::Int {
            bits: 8,
            signedness: Signedness::Unsigned,
        } => "uint8_t".to_string(),
        CTypeLike::Int {
            bits: 16,
            signedness: Signedness::Unsigned,
        } => "uint16_t".to_string(),
        CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Unsigned,
        } => "uint32_t".to_string(),
        CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        } => "uint64_t".to_string(),
        // A 128-bit integer has exactly one spelling a C compiler accepts, and
        // `uint128_t` is not it. `r2dec` already knew this for the C it emits;
        // this renderer feeds radare2's type database, which had been getting a
        // type name no compiler would take.
        CTypeLike::Int {
            bits: 128,
            signedness: Signedness::Unsigned,
        } => "__uint128_t".to_string(),
        CTypeLike::Int {
            bits,
            signedness: Signedness::Unsigned,
        } => format!("uint{bits}_t"),
        CTypeLike::Float(32) => "float".to_string(),
        CTypeLike::Float(64) => "double".to_string(),
        CTypeLike::Float(bits) => format!("float{bits}"),
        CTypeLike::BitVector(bits) => format!("struct {}", bit_vector_tag(*bits)),
        CTypeLike::Pointer(inner) => format!("{}*", render_c_type_like(inner)),
        CTypeLike::Array(inner, Some(size)) => format!("{}[{}]", render_c_type_like(inner), size),
        CTypeLike::Array(inner, None) => format!("{}[]", render_c_type_like(inner)),
        CTypeLike::Struct(name) => format!("struct {name}"),
        CTypeLike::Union(name) => format!("union {name}"),
        CTypeLike::Enum(name) => format!("enum {name}"),
        CTypeLike::Typedef { name, .. } => name.clone(),
        CTypeLike::Const(inner) => format!("const {}", render_c_type_like(inner)),
        CTypeLike::Function { ret, params } => {
            // A function proven to take nothing is spelled `(void)`. An empty
            // list says the arguments are unspecified, which is a weaker claim
            // than the one the call site proved, and C23 removed it.
            let params = if params.is_empty() {
                "void".to_string()
            } else {
                params
                    .iter()
                    .map(render_c_type_like)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!("{}(*)({params})", render_c_type_like(ret))
        }
        CTypeLike::Unknown => "/* unknown */".to_string(),
    }
}

/// The same type with anything C cannot spell replaced by the storage it names.
///
/// `/* unknown */` is a comment, not a type: a declaration carrying one is not
/// C and the translation unit is rejected. Where the recovery reached no type,
/// the machine word the value occupies stands, which is the rule a parameter
/// with no evidence already follows. Behind a pointer the same absence is
/// `void`, because `void *` is what C spells for a pointer to something
/// unknown.
pub fn spellable_c_type_like(ty: &CTypeLike, machine_bits: u32) -> CTypeLike {
    match ty {
        CTypeLike::Unknown => CTypeLike::machine_bits(machine_bits),
        CTypeLike::Pointer(inner) => CTypeLike::Pointer(Box::new(match inner.as_ref() {
            CTypeLike::Unknown => CTypeLike::Void,
            other => spellable_c_type_like(other, machine_bits),
        })),
        CTypeLike::Array(inner, extent) => CTypeLike::Array(
            Box::new(spellable_c_type_like(inner, machine_bits)),
            *extent,
        ),
        CTypeLike::Function { ret, params } => CTypeLike::Function {
            ret: Box::new(spellable_c_type_like(ret, machine_bits)),
            params: params
                .iter()
                .map(|param| spellable_c_type_like(param, machine_bits))
                .collect(),
        },
        other => other.clone(),
    }
}

/// A declaration of `name` at this type, as C spells it.
///
/// C puts the identifier *inside* the declarator rather than after the type,
/// and only a scalar or a pointer to one makes the two look the same. An array
/// takes its extent after the name, and a function pointer wraps the name --
/// `void (*handler)(void)`, never `void(*)(void) handler`, which is what
/// appending the name to the type spelling produced.
pub fn c_object_declaration(ty: &CTypeLike, name: &str) -> String {
    let mut declarator = name.to_string();
    let mut element = ty;
    loop {
        match element {
            CTypeLike::Array(inner, extent) => {
                declarator.push('[');
                if let Some(extent) = extent {
                    declarator.push_str(&extent.to_string());
                }
                declarator.push(']');
                element = inner;
            }
            // `Function` is the model's spelling for a pointer to function, so
            // the name goes where that pointer's `*` is.
            CTypeLike::Function { ret, params } => {
                let params = if params.is_empty() {
                    "void".to_string()
                } else {
                    params
                        .iter()
                        .map(render_c_type_like)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                declarator = format!("(*{declarator})({params})");
                element = ret;
            }
            // A pointer binds looser than the array or call that follows it,
            // so it needs the parentheses C would otherwise read the other way.
            CTypeLike::Pointer(inner)
                if matches!(
                    inner.as_ref(),
                    CTypeLike::Array(..) | CTypeLike::Function { .. }
                ) =>
            {
                declarator = format!("(*{declarator})");
                element = inner;
            }
            _ => break,
        }
    }
    let base = render_c_type_like(element);
    if declarator.is_empty() {
        base
    } else {
        format!("{base} {declarator}")
    }
}

/// Parse a C type spelling into the model.
///
/// This is the partial inverse of `render_c_type_like`. A spelling is data
/// arriving from radare2's type database, from DWARF, or from our own renderer,
/// so the parser accepts more spellings than the renderer emits -- `unsigned
/// int` as well as `uint32_t`, `char *` as well as `char*`. It still refuses a
/// spelling it cannot place instead of minting a plausible typedef from
/// malformed text.
///
/// `ptr_bits` is a parameter rather than an assumption because the width of
/// `long` and `size_t` is a property of the target, and guessing it is how two
/// of the previous parsers came to disagree.
pub fn parse_c_type_like(spelling: &str, ptr_bits: u32) -> Option<CTypeLike> {
    // A pointer level is peeled before the qualifiers go, because the
    // qualifier of what it points at is part of the pointer's type. What
    // follows the star qualifies the pointer itself and is dropped with the
    // rest.
    let spelling = spelling.trim();
    if let Some(inner) = spelling.strip_suffix('*') {
        let pointee = parse_c_type_like(inner, ptr_bits)?;
        let pointee = if !matches!(pointee, CTypeLike::Pointer(_) | CTypeLike::Const(_))
            && spells_const(inner)
        {
            CTypeLike::Const(Box::new(pointee))
        } else {
            pointee
        };
        return Some(CTypeLike::Pointer(Box::new(pointee)));
    }
    let normalized = crate::external::normalize_type_spelling(spelling);
    parse_normalized(normalized.trim(), ptr_bits)
}

/// Whether a spelling carries `const` as a word of its own.
fn spells_const(spelling: &str) -> bool {
    spelling
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .any(|token| matches!(token, "const" | "__const" | "__const__"))
}

fn parse_normalized(spelling: &str, ptr_bits: u32) -> Option<CTypeLike> {
    let spelling = spelling.trim();
    if spelling.is_empty() {
        return None;
    }
    if matches!(
        spelling.to_ascii_lowercase().as_str(),
        "/* unknown */" | "unknown" | "unknown_t" | "undefined" | "undefined_t"
    ) {
        return Some(CTypeLike::Unknown);
    }
    if let Some(inner) = spelling.strip_suffix('*') {
        return Some(CTypeLike::Pointer(Box::new(parse_normalized(
            inner, ptr_bits,
        )?)));
    }
    if let Some(open) = spelling.rfind('[')
        && spelling.ends_with(']')
    {
        let len = spelling[open + 1..spelling.len() - 1].trim();
        let len = if len.is_empty() {
            None
        } else {
            Some(len.parse::<usize>().ok()?)
        };
        return Some(CTypeLike::Array(
            Box::new(parse_normalized(&spelling[..open], ptr_bits)?),
            len,
        ));
    }
    if let Some(bits) = spelling
        .strip_prefix("struct ")
        .and_then(|tag| tag.strip_prefix(BIT_VECTOR_TAG_PREFIX))
        .and_then(|bits| bits.parse::<u32>().ok())
    {
        return Some(CTypeLike::BitVector(bits));
    }
    for (keyword, build) in [
        ("struct ", CTypeLike::Struct as fn(String) -> CTypeLike),
        ("union ", CTypeLike::Union as fn(String) -> CTypeLike),
        ("enum ", CTypeLike::Enum as fn(String) -> CTypeLike),
    ] {
        if let Some(name) = spelling.strip_prefix(keyword) {
            let name = name.trim();
            return is_c_type_identifier(name).then(|| build(name.to_string()));
        }
    }
    if spelling.contains("(*)") {
        // A spelling reached here only says it is a function pointer; the
        // signature it was written with is not recovered from the text.
        return Some(CTypeLike::Function {
            ret: Box::new(CTypeLike::Unknown),
            params: Box::new([]),
        });
    }

    let collapsed = spelling.split_whitespace().collect::<Vec<_>>().join(" ");
    let classification = collapsed.to_ascii_lowercase();
    if let Some(width) = fixed_width_integer(&classification) {
        return Some(width);
    }
    match classification.as_str() {
        "void" => Some(CTypeLike::Void),
        "bool" | "_bool" => Some(CTypeLike::Bool),
        "float" => Some(CTypeLike::Float(32)),
        "double" | "long double" => Some(CTypeLike::Float(64)),
        _ => named_integer_bits(&classification, ptr_bits)
            .map(|(bits, signedness)| CTypeLike::Int { bits, signedness })
            .or_else(|| is_c_type_identifier(&collapsed).then(|| CTypeLike::typedef(collapsed))),
    }
}

/// Whether a spelling *names* a type rather than being a way of writing one.
///
/// `size_t` is a name: it renders as itself and a declaration can say what it
/// stands for. `unsigned int` is not -- it is the type, written out, and
/// treating it as a name produced `typedef uint32_t unsigned int;`, which no
/// compiler accepts. The test is the language's: one identifier, and not one
/// of the specifier keywords.
pub fn spelling_names_a_type(spelling: &str) -> bool {
    let trimmed = spelling.trim();
    is_c_type_identifier(trimmed)
        && !matches!(
            trimmed,
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "signed"
                | "unsigned"
                | "_Bool"
                | "bool"
                | "const"
                | "volatile"
        )
}

fn is_c_type_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// The `intN_t` family, including the `__int128_t` spelling that is the only
/// one a C compiler accepts for that width.
fn fixed_width_integer(spelling: &str) -> Option<CTypeLike> {
    let (rest, signedness) = match spelling
        .strip_prefix("__")
        .unwrap_or(spelling)
        .strip_prefix('u')
    {
        Some(rest) => (rest, Signedness::Unsigned),
        None => (
            spelling.strip_prefix("__").unwrap_or(spelling),
            Signedness::Signed,
        ),
    };
    let bits = rest.strip_prefix("int")?.strip_suffix("_t")?;
    Some(CTypeLike::Int {
        bits: bits.parse::<u32>().ok()?,
        signedness,
    })
}

/// The spellings whose width depends on the target, plus the plain C keywords.
fn named_integer_bits(spelling: &str, ptr_bits: u32) -> Option<(u32, Signedness)> {
    // The declared names first: each stands for one integer type and none of
    // them combines with a specifier.
    match spelling {
        "size_t" | "uintptr_t" => return Some((ptr_bits, Signedness::Unsigned)),
        "ssize_t" | "intptr_t" | "ptrdiff_t" => return Some((ptr_bits, Signedness::Signed)),
        _ => {}
    }
    // Then the specifiers, in any order, because C says their order is
    // immaterial and the debug information takes it at its word: GCC writes
    // `long unsigned int`, which no leading-`unsigned` rule reads.
    let mut signed = None;
    let mut longs = 0u32;
    let mut short = false;
    let mut char_ = false;
    let mut int = false;
    for token in spelling.split_whitespace() {
        match token {
            "unsigned" => signed = Some(Signedness::Unsigned),
            "signed" => signed = Some(Signedness::Signed),
            "long" => longs += 1,
            "short" => short = true,
            "char" => char_ = true,
            "int" => int = true,
            _ => return None,
        }
    }
    // `unsigned` alone is `unsigned int`; `long` alone is `long int`.
    if !(int || char_ || short || longs > 0 || signed.is_some()) {
        return None;
    }
    // A `char` is neither `short` nor `long` and a `short` is not `long`, so a
    // spelling combining them is not a type this states a width for.
    if char_ && (short || longs > 0 || int) || (short && longs > 0) || longs > 2 {
        return None;
    }
    let bits = match (char_, short, longs) {
        (true, _, _) => 8,
        (_, true, _) => 16,
        (_, _, 0) => 32,
        (_, _, 1) => ptr_bits,
        (_, _, _) => 64,
    };
    Some((bits, signed.unwrap_or(Signedness::Signed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// C says the order of type specifiers is immaterial, and the debug
    /// information takes it at its word: GCC writes `long unsigned int`.
    #[test]
    fn integer_specifiers_are_read_in_any_order() {
        let unsigned_long = CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        };
        for spelling in ["unsigned long", "long unsigned", "long unsigned int"] {
            assert_eq!(
                parse_c_type_like(spelling, 64),
                Some(unsigned_long.clone()),
                "{spelling}"
            );
        }
        assert_eq!(
            parse_c_type_like("short unsigned int", 64),
            Some(CTypeLike::Int {
                bits: 16,
                signedness: Signedness::Unsigned
            })
        );
        assert_eq!(
            parse_c_type_like("long long unsigned int", 64),
            Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned
            })
        );
    }

    /// A run of specifiers that names no type states no width.
    #[test]
    fn specifiers_that_do_not_combine_name_nothing() {
        for spelling in ["short long", "long char", "short char int"] {
            assert_eq!(parse_c_type_like(spelling, 64), None, "{spelling}");
        }
    }

    /// radare2's own spellings, which arrive dotted and unspaced.
    ///
    /// These are what `canonical type spelling` was rewriting by
    /// hand, searching a rendered string for the first `*` and inserting a
    /// space in front of it. Parsing reaches the same type from every spelling,
    /// so the normalisation belongs at the point the spelling arrives rather
    /// than at each point one is consumed.
    #[test]
    fn radare_dotted_spellings_reach_the_same_type() {
        let foo = CTypeLike::Pointer(Box::new(CTypeLike::Struct("Foo".to_string())));
        for spelling in ["struct.Foo*", "struct.Foo *", "struct Foo*", "struct Foo *"] {
            assert_eq!(
                parse_c_type_like(spelling, 64),
                Some(foo.clone()),
                "{spelling}"
            );
        }
        assert_eq!(
            parse_c_type_like("union.Bar*", 64),
            Some(CTypeLike::Pointer(Box::new(CTypeLike::Union(
                "Bar".to_string()
            ))))
        );
        assert_eq!(
            parse_c_type_like("type.Foo", 64),
            Some(CTypeLike::typedef("Foo"))
        );
    }

    #[test]
    fn unplaceable_spellings_are_refused_instead_of_becoming_types() {
        for spelling in [
            "",
            "not a type",
            "type.Namespace.member",
            "not a type *",
            "uint8_t[not-a-length]",
            "struct Name trailing",
        ] {
            assert_eq!(parse_c_type_like(spelling, 64), None, "{spelling}");
        }
    }

    #[test]
    fn qualified_pointer_spellings_reach_the_same_type() {
        let signed_char_ptr =
            CTypeLike::Pointer(Box::new(CTypeLike::Const(Box::new(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Signed,
            }))));
        let void_ptr = CTypeLike::Pointer(Box::new(CTypeLike::Const(Box::new(CTypeLike::Void))));

        for spelling in ["char const *", "char const*", "const char *"] {
            assert_eq!(
                parse_c_type_like(spelling, 64),
                Some(signed_char_ptr.clone()),
                "{spelling}"
            );
        }
        assert_eq!(parse_c_type_like("void __const*", 64), Some(void_ptr));
    }

    #[test]
    fn external_typedef_pointer_is_structurally_placeable() {
        assert_eq!(
            parse_c_type_like("FILE *", 64),
            Some(CTypeLike::Pointer(Box::new(CTypeLike::typedef("FILE"))))
        );
    }

    #[test]
    fn c_bool_spellings_reach_the_same_type() {
        assert_eq!(parse_c_type_like("_Bool", 64), Some(CTypeLike::Bool));
        assert_eq!(
            parse_c_type_like("_Bool *", 64),
            Some(CTypeLike::Pointer(Box::new(CTypeLike::Bool)))
        );
    }

    /// Every type the renderer can emit, rendered and parsed back.
    ///
    /// This is the property the seam depends on: a type that survives a trip
    /// through its own spelling is one that can safely be stored as a spelling
    /// at a boundary that needs one. Any case that fails is a place where a
    /// string is lossy and the type must be carried instead.
    #[test]
    fn every_rendered_type_parses_back_to_itself() {
        let mut cases = vec![
            CTypeLike::Void,
            CTypeLike::Bool,
            CTypeLike::Float(32),
            CTypeLike::Float(64),
            CTypeLike::Struct("Demo".to_string()),
            CTypeLike::Union("Demo".to_string()),
            CTypeLike::Enum("Demo".to_string()),
            CTypeLike::typedef("demo_t"),
            CTypeLike::Unknown,
            CTypeLike::Function {
                ret: Box::new(CTypeLike::Unknown),
                params: Box::new([]),
            },
        ];
        for bits in [8u32, 16, 32, 64, 128] {
            for signedness in [Signedness::Signed, Signedness::Unsigned] {
                cases.push(CTypeLike::Int { bits, signedness });
            }
        }
        let scalars = cases.clone();
        for scalar in scalars {
            cases.push(CTypeLike::Pointer(Box::new(scalar.clone())));
            cases.push(CTypeLike::Array(Box::new(scalar), Some(4)));
        }

        let mut lossy = Vec::new();
        for case in &cases {
            let rendered = render_c_type_like(case);
            let parsed = parse_c_type_like(&rendered, 64);
            if parsed.as_ref() != Some(case) {
                lossy.push(format!("{case:?} rendered {rendered:?} parsed {parsed:?}"));
            }
        }
        assert!(
            lossy.is_empty(),
            "types lost through their spelling:\n{}",
            lossy.join("\n")
        );
    }

    /// The spellings that arrive from radare2 and DWARF rather than from us.
    #[test]
    fn external_spellings_parse_to_the_same_types_our_own_do() {
        let ptr_bits = 64;
        for (spelling, expected) in [
            (
                "unsigned int",
                CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Unsigned,
                },
            ),
            (
                "int",
                CTypeLike::Int {
                    bits: 32,
                    signedness: Signedness::Signed,
                },
            ),
            (
                "unsigned char",
                CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unsigned,
                },
            ),
            (
                "long",
                CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Signed,
                },
            ),
            (
                "size_t",
                CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Unsigned,
                },
            ),
            (
                "char *",
                CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Signed,
                })),
            ),
            (
                "const char *",
                CTypeLike::Pointer(Box::new(CTypeLike::Const(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Signed,
                })))),
            ),
            (
                "struct Demo *",
                CTypeLike::Pointer(Box::new(CTypeLike::Struct("Demo".to_string()))),
            ),
            (
                "__uint128_t",
                CTypeLike::Int {
                    bits: 128,
                    signedness: Signedness::Unsigned,
                },
            ),
            (
                "uint64_t",
                CTypeLike::Int {
                    bits: 64,
                    signedness: Signedness::Unsigned,
                },
            ),
        ] {
            assert_eq!(
                parse_c_type_like(spelling, ptr_bits),
                Some(expected),
                "{spelling}"
            );
        }
    }

    /// A width whose signedness is unknown cannot survive a spelling.
    ///
    /// C has no way to write "thirty-two bits, signedness not established", so
    /// the renderer has to pick one and picks signed. That is not a bug in the
    /// renderer -- it is the reason a type must be carried as a type across the
    /// type boundary rather than as the string it renders to, because the
    /// boundary is exactly where the distinction is still live.
    #[test]
    fn unknown_signedness_is_the_one_thing_a_spelling_cannot_carry() {
        let unknown = CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Unknown,
        };
        assert_eq!(render_c_type_like(&unknown), "int32_t");
        assert_eq!(
            parse_c_type_like("int32_t", 64),
            Some(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed,
            })
        );
    }

    /// `long` is target-width, so the caller supplies the width.
    #[test]
    fn target_width_spellings_follow_the_pointer_width_given() {
        assert_eq!(
            parse_c_type_like("long", 32),
            Some(CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed
            })
        );
        assert_eq!(
            parse_c_type_like("long", 64),
            Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed
            })
        );
    }

    #[test]
    fn render_c_type_like_preserves_unknown_without_materializing() {
        assert_eq!(render_c_type_like(&CTypeLike::Unknown), "/* unknown */");
        assert_eq!(
            render_c_type_like(&CTypeLike::Pointer(Box::new(CTypeLike::Unknown))),
            "/* unknown */*"
        );
    }

    #[test]
    fn render_c_type_like_formats_named_and_integer_types() {
        assert_eq!(
            render_c_type_like(&CTypeLike::Int {
                bits: 32,
                signedness: Signedness::Signed
            }),
            "int32_t"
        );
        assert_eq!(
            render_c_type_like(&CTypeLike::Struct("Demo".to_string())),
            "struct Demo"
        );
    }
}
