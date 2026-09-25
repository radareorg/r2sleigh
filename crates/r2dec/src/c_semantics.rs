//! ISO C's integer semantics over the tree the emitter prints.
//!
//! A proof harness asks what a rendering computes, and the answer has to come
//! from C's rules rather than from the machine operation the rendering was
//! lowered from: a spelling can look like the operation and mean something
//! else once C promotes it. `~(uint8_t)0` is the `int` -1, not the byte
//! 0xff, and a mask built from it erased every bit above the byte it named.
//!
//! This interprets a straight-line rendered body -- declarations,
//! assignments, loads and stores through constant addresses, `if`, `return`
//! -- under C11 on an LP64 target, `int` being 32 bits:
//!
//! - integer promotion (6.3.1.1p2): every type narrower than `int` becomes
//!   `int` before an operator applies;
//! - the usual arithmetic conversions (6.3.1.8) between the promoted operands
//!   of a binary operator;
//! - conversions (6.3.1.3), modular to an unsigned type and, as GCC and Clang
//!   define the implementation-defined case, modular to a signed one;
//! - shifts (6.5.7): each operand promoted on its own, the result at the left
//!   operand's promoted type.
//!
//! A literal has the type C gives the text the emitter prints for it
//! (6.4.4.1), so a literal the emitter spells as a negation is evaluated as
//! one. Undefined behaviour -- a signed overflow, a shift by at least the
//! width, a read of an object nothing wrote -- is reported rather than
//! computed through. Anything the interpreter does not model is refused
//! outright, so no harness can pass by evaluating something it does not
//! understand.

use std::collections::BTreeMap;

use crate::ast::{BinaryOp, CExpr, CFunction, CStmt, CType, UnaryOp};
use crate::symbol::{SymbolId, SymbolTable};

/// An integer type: its width in bits and whether it is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntType {
    bits: u32,
    signed: bool,
}

impl IntType {
    const INT: Self = Self {
        bits: 32,
        signed: true,
    };

    const fn unsigned(bits: u32) -> Self {
        Self {
            bits,
            signed: false,
        }
    }

    const fn mask(self) -> u128 {
        if self.bits >= 128 {
            u128::MAX
        } else {
            (1u128 << self.bits) - 1
        }
    }

    /// 6.3.1.1p2: every value of a type narrower than `int` fits in `int`.
    const fn promoted(self) -> Self {
        if self.bits < 32 { Self::INT } else { self }
    }
}

/// A value and the type C gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Value {
    /// The object representation, reduced to the type's width.
    bits: u128,
    ty: IntType,
}

impl Value {
    const fn new(bits: u128, ty: IntType) -> Self {
        Self {
            bits: bits & ty.mask(),
            ty,
        }
    }

    /// The representation sign-extended to 128 bits where the type is signed
    /// and the value negative, zero-extended otherwise.
    fn extended(self) -> u128 {
        let negative = self.ty.signed && (self.bits >> (self.ty.bits - 1)) & 1 == 1;
        if negative {
            self.bits | !self.ty.mask()
        } else {
            self.bits
        }
    }

    /// The mathematical value, which for every width here fits an `i128`
    /// except an unsigned 128-bit one above `i128::MAX`.
    fn integer(self) -> Option<i128> {
        if self.ty.signed {
            Some(self.extended() as i128)
        } else {
            i128::try_from(self.bits).ok()
        }
    }

    fn is_zero(self) -> bool {
        self.bits == 0
    }

    /// 6.3.1.3: the value converted to `to`, modular in both directions.
    fn convert(self, to: IntType) -> Self {
        Self::new(self.extended(), to)
    }

    fn promote(self) -> Self {
        self.convert(self.ty.promoted())
    }
}

/// Why an evaluation stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The C has undefined behaviour here.
    Undefined(String),
    /// The interpreter does not model this construct.
    Unmodelled(String),
}

type Eval<T> = Result<T, Stop>;

fn undefined<T>(why: impl Into<String>) -> Eval<T> {
    Err(Stop::Undefined(why.into()))
}

fn unmodelled<T>(what: impl std::fmt::Debug) -> Eval<T> {
    Err(Stop::Unmodelled(format!("{what:?}")))
}

/// The integer type a C type names, a pointer being its 64-bit address.
fn int_type(ty: &CType) -> Eval<IntType> {
    match ty {
        CType::Int { bits, signedness } if matches!(bits, 8 | 16 | 32 | 64 | 128) => Ok(IntType {
            bits: *bits,
            signed: *signedness == r2types::Signedness::Signed,
        }),
        CType::Bool => Ok(IntType::unsigned(1)),
        CType::Pointer(_) => Ok(IntType::unsigned(64)),
        CType::Typedef { ty, .. } | CType::Const(ty) => int_type(ty),
        other => unmodelled(other),
    }
}

/// 6.3.1.8 over two operands already promoted.
fn usual_arithmetic(left: IntType, right: IntType) -> IntType {
    if left.signed == right.signed {
        return if left.bits >= right.bits { left } else { right };
    }
    let (unsigned, signed) = if left.signed {
        (right, left)
    } else {
        (left, right)
    };
    if unsigned.bits >= signed.bits {
        unsigned
    } else {
        // A signed type strictly wider than the unsigned one represents all
        // of its values.
        signed
    }
}

/// The type 6.4.4.1 gives the digits the emitter prints, before any sign;
/// none where no standard type holds them.
fn literal_type(magnitude: u64, hexadecimal: bool, unsigned_suffix: bool) -> Option<IntType> {
    let candidates: &[IntType] = match (unsigned_suffix, hexadecimal) {
        (true, _) => &[IntType::unsigned(32), IntType::unsigned(64)],
        (false, false) => &[
            IntType::INT,
            IntType {
                bits: 64,
                signed: true,
            },
        ],
        (false, true) => &[
            IntType::INT,
            IntType::unsigned(32),
            IntType {
                bits: 64,
                signed: true,
            },
            IntType::unsigned(64),
        ],
    };
    candidates.iter().copied().find(|ty| {
        let max = if ty.signed { ty.mask() >> 1 } else { ty.mask() };
        u128::from(magnitude) <= max
    })
}

/// The value of a literal as the emitter prints it.
fn literal(expr: &CExpr) -> Option<Eval<Value>> {
    let digits = |magnitude: u64, hexadecimal: bool, suffix: bool| {
        literal_type(magnitude, hexadecimal, suffix)
            .map(|ty| Value::new(u128::from(magnitude), ty))
            .ok_or_else(|| Stop::Unmodelled(format!("literal {magnitude:#x} has no type")))
    };
    // How the emitter spells an unsigned magnitude.
    let hexadecimal =
        |magnitude: u64| crate::codegen::format_unsigned_literal(magnitude).starts_with("0x");
    Some(match expr {
        CExpr::IntLit(value) => match u64::try_from(*value) {
            Ok(magnitude) => digits(magnitude, hexadecimal(magnitude), false),
            // Printed as `-N` in decimal: the negation of a decimal literal.
            Err(_) => digits(value.unsigned_abs(), false, false).and_then(negate),
        },
        CExpr::UIntLit(value) if *value > crate::codegen::LIKELY_NEGATIVE_THRESHOLD => {
            // Printed as `-0xN` with no suffix: the negation of a hexadecimal
            // literal, which is what C reads whatever the tree meant.
            digits((!*value).wrapping_add(1), true, false).and_then(negate)
        }
        CExpr::UIntLit(value) => digits(*value, hexadecimal(*value), true),
        _ => return None,
    })
}

fn negate(value: Value) -> Eval<Value> {
    let value = value.promote();
    if value.ty.signed && value.integer() == Some(-(1i128 << (value.ty.bits - 1))) {
        return undefined(format!("-{value:?} overflows"));
    }
    Ok(Value::new(value.bits.wrapping_neg(), value.ty))
}

/// A signed result is defined only where the mathematical one fits.
fn checked_signed(result: i128, ty: IntType, what: &str) -> Eval<Value> {
    let min = -(1i128 << (ty.bits - 1));
    let max = (1i128 << (ty.bits - 1)) - 1;
    if result < min || result > max {
        return undefined(format!("{what} overflows {ty:?}"));
    }
    Ok(Value::new(result as u128, ty))
}

/// An interpreter over one rendered function's integer statements.
pub(crate) struct Interpreter<'a> {
    symbols: &'a SymbolTable,
    objects: BTreeMap<SymbolId, Value>,
    /// Bytes at addresses, little-endian; a read of a byte nothing wrote is
    /// undefined here, since the harness wrote every byte it means to be read.
    memory: BTreeMap<u64, u8>,
}

impl<'a> Interpreter<'a> {
    pub(crate) fn new(symbols: &'a SymbolTable) -> Self {
        Self {
            symbols,
            objects: BTreeMap::new(),
            memory: BTreeMap::new(),
        }
    }

    pub(crate) fn write_memory(&mut self, address: u64, value: u128, bytes: u32) {
        for index in 0..bytes {
            self.memory
                .insert(address + u64::from(index), (value >> (8 * index)) as u8);
        }
    }

    pub(crate) fn read_memory(&self, address: u64, bytes: u32) -> Eval<u128> {
        (0..bytes).try_fold(0u128, |value, index| {
            let byte = self
                .memory
                .get(&(address + u64::from(index)))
                .ok_or_else(|| {
                    Stop::Undefined(format!("read of unwritten byte {address:#x}+{index}"))
                })?;
            Ok(value | u128::from(*byte) << (8 * index))
        })
    }

    /// Call the function with its parameters holding `arguments`, in order,
    /// and answer what it returns, at its declared type.
    pub(crate) fn call(&mut self, function: &CFunction, arguments: &[u128]) -> Eval<Option<Value>> {
        if function.params.len() != arguments.len() {
            return unmodelled(("arity", function.params.len(), arguments.len()));
        }
        for (param, argument) in function.params.iter().zip(arguments) {
            let ty = int_type(&param.ty)?;
            self.objects.insert(param.name, Value::new(*argument, ty));
        }
        match self.block(&function.body)? {
            Flow::Return(Some(value)) => Ok(Some(self.convert_to(value, &function.ret_type)?)),
            Flow::Return(None) | Flow::Next => Ok(None),
        }
    }

    fn block(&mut self, body: &[CStmt]) -> Eval<Flow> {
        for stmt in body {
            if let Flow::Return(value) = self.stmt(stmt)? {
                return Ok(Flow::Return(value));
            }
        }
        Ok(Flow::Next)
    }

    fn stmt(&mut self, stmt: &CStmt) -> Eval<Flow> {
        match stmt {
            CStmt::Observed { stmt, .. } | CStmt::StructuredRegion { stmt, .. } => self.stmt(stmt),
            CStmt::Empty | CStmt::Comment(_) | CStmt::Label(_) => Ok(Flow::Next),
            CStmt::Block(body) => self.block(body),
            CStmt::Expr(expr) => self.expr(expr).map(|_| Flow::Next),
            CStmt::Decl { ty, name, init } => {
                if let Some(init) = init {
                    let value = self.expr(init)?;
                    let value = self.convert_to(value, ty)?;
                    self.objects.insert(*name, value);
                }
                Ok(Flow::Next)
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                if !self.expr(cond)?.is_zero() {
                    self.stmt(then_body)
                } else if let Some(else_body) = else_body {
                    self.stmt(else_body)
                } else {
                    Ok(Flow::Next)
                }
            }
            CStmt::Return(value) => Ok(Flow::Return(match value {
                Some(value) => Some(self.expr(value)?),
                None => None,
            })),
            other => unmodelled(other),
        }
    }

    fn convert_to(&self, value: Value, ty: &CType) -> Eval<Value> {
        let to = int_type(ty)?;
        if to.bits == 1 {
            return Ok(Value::new(u128::from(!value.is_zero()), to));
        }
        Ok(value.convert(to))
    }

    /// The declared type of an object the function names.
    fn declared(&self, symbol: SymbolId) -> Eval<IntType> {
        int_type(self.symbols.ty(symbol))
    }

    /// Where an lvalue is, and what type it has there.
    fn place(&mut self, expr: &CExpr) -> Eval<Place> {
        match expr {
            CExpr::Observed { expr, .. } | CExpr::Paren(expr) => self.place(expr),
            CExpr::Var(symbol) => Ok(Place::Object(*symbol, self.declared(*symbol)?)),
            CExpr::Deref(pointer) => {
                let (address, pointee) = self.pointer(pointer)?;
                Ok(Place::Memory(address, pointee))
            }
            other => unmodelled(other),
        }
    }

    /// A pointer operand: its address and the type it points at.
    fn pointer(&mut self, expr: &CExpr) -> Eval<(u64, IntType)> {
        match expr {
            CExpr::Observed { expr, .. } | CExpr::Paren(expr) => self.pointer(expr),
            CExpr::Cast {
                ty: CType::Pointer(pointee),
                expr,
                ..
            } => {
                let address = self.expr(expr)?.convert(IntType::unsigned(64)).bits as u64;
                Ok((address, int_type(pointee)?))
            }
            other => unmodelled(other),
        }
    }

    fn load(&self, place: Place) -> Eval<Value> {
        match place {
            Place::Object(symbol, _) => self.objects.get(&symbol).copied().ok_or_else(|| {
                Stop::Undefined(format!(
                    "read of {} before anything wrote it",
                    self.symbols.name(symbol)
                ))
            }),
            Place::Memory(address, ty) => Ok(Value::new(
                self.read_memory(address, ty.bits.div_ceil(8))?,
                ty,
            )),
        }
    }

    fn store(&mut self, place: Place, value: Value) {
        match place {
            Place::Object(symbol, ty) => {
                self.objects.insert(symbol, value.convert(ty));
            }
            Place::Memory(address, ty) => {
                let value = value.convert(ty);
                self.write_memory(address, value.bits, ty.bits.div_ceil(8));
            }
        }
    }

    fn expr(&mut self, expr: &CExpr) -> Eval<Value> {
        if let Some(value) = literal(expr) {
            return value;
        }
        match expr {
            CExpr::Observed { expr, .. } | CExpr::Paren(expr) => self.expr(expr),
            CExpr::Var(_) | CExpr::Deref(_) => {
                let place = self.place(expr)?;
                self.load(place)
            }
            CExpr::Cast { ty, expr, .. } => {
                let value = self.expr(expr)?;
                self.convert_to(value, ty)
            }
            CExpr::Unary { op, operand } => {
                let value = self.expr(operand)?;
                match op {
                    UnaryOp::BitNot => {
                        let value = value.promote();
                        Ok(Value::new(!value.bits, value.ty))
                    }
                    UnaryOp::Neg => negate(value),
                    UnaryOp::Not => Ok(Value::new(u128::from(value.is_zero()), IntType::INT)),
                    other => unmodelled(other),
                }
            }
            CExpr::Binary { op, left, right } => self.binary(*op, left, right),
            // A conditional's type is the arms' converted type (6.5.15p5),
            // which needs the type of the arm not evaluated; that is not
            // modelled, so it is not guessed.
            other => unmodelled(other),
        }
    }

    fn binary(&mut self, op: BinaryOp, left: &CExpr, right: &CExpr) -> Eval<Value> {
        let compound = match op {
            BinaryOp::Assign => None,
            BinaryOp::AddAssign => Some(BinaryOp::Add),
            BinaryOp::SubAssign => Some(BinaryOp::Sub),
            BinaryOp::MulAssign => Some(BinaryOp::Mul),
            BinaryOp::DivAssign => Some(BinaryOp::Div),
            BinaryOp::ModAssign => Some(BinaryOp::Mod),
            BinaryOp::BitAndAssign => Some(BinaryOp::BitAnd),
            BinaryOp::BitOrAssign => Some(BinaryOp::BitOr),
            BinaryOp::BitXorAssign => Some(BinaryOp::BitXor),
            BinaryOp::ShlAssign => Some(BinaryOp::Shl),
            BinaryOp::ShrAssign => Some(BinaryOp::Shr),
            BinaryOp::And | BinaryOp::Or => {
                let first = !self.expr(left)?.is_zero();
                let result = match op {
                    BinaryOp::And => first && !self.expr(right)?.is_zero(),
                    _ => first || !self.expr(right)?.is_zero(),
                };
                return Ok(Value::new(u128::from(result), IntType::INT));
            }
            _ => {
                let left = self.expr(left)?;
                let right = self.expr(right)?;
                return arithmetic(op, left, right);
            }
        };
        let place = self.place(left)?;
        let value = self.expr(right)?;
        let value = match compound {
            // 6.5.16.2p3: `E1 op= E2` is `E1 = E1 op (E2)`, E1 read once.
            Some(op) => arithmetic(op, self.load(place)?, value)?,
            None => value,
        };
        self.store(place, value);
        self.load(place)
    }
}

#[derive(Debug, Clone, Copy)]
enum Place {
    Object(SymbolId, IntType),
    Memory(u64, IntType),
}

enum Flow {
    Next,
    Return(Option<Value>),
}

/// A binary operator over two evaluated operands.
fn arithmetic(op: BinaryOp, left: Value, right: Value) -> Eval<Value> {
    if matches!(op, BinaryOp::Shl | BinaryOp::Shr) {
        return shift(op, left.promote(), right.promote());
    }
    let ty = usual_arithmetic(left.ty.promoted(), right.ty.promoted());
    let (l, r) = (left.convert(ty), right.convert(ty));
    let boolean = |truth: bool| Ok(Value::new(u128::from(truth), IntType::INT));
    // Both operands are at `ty` now, so one of the two orders is the order.
    let ordering = if ty.signed {
        (l.extended() as i128).cmp(&(r.extended() as i128))
    } else {
        l.bits.cmp(&r.bits)
    };
    match op {
        BinaryOp::BitAnd => Ok(Value::new(l.bits & r.bits, ty)),
        BinaryOp::BitOr => Ok(Value::new(l.bits | r.bits, ty)),
        BinaryOp::BitXor => Ok(Value::new(l.bits ^ r.bits, ty)),
        BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            ring(op, l, r, ty)
        }
        BinaryOp::Eq => boolean(ordering.is_eq()),
        BinaryOp::Ne => boolean(ordering.is_ne()),
        BinaryOp::Lt => boolean(ordering.is_lt()),
        BinaryOp::Le => boolean(ordering.is_le()),
        BinaryOp::Gt => boolean(ordering.is_gt()),
        BinaryOp::Ge => boolean(ordering.is_ge()),
        other => unmodelled(other),
    }
}

/// `+ - * / %` over two operands at `ty`: modular where `ty` is unsigned
/// (6.2.5p9), and defined only where the result fits where it is signed
/// (6.5p5); a division by zero is undefined either way (6.5.5p5).
fn ring(op: BinaryOp, l: Value, r: Value, ty: IntType) -> Eval<Value> {
    if matches!(op, BinaryOp::Div | BinaryOp::Mod) && r.is_zero() {
        return undefined("division by zero");
    }
    if !ty.signed {
        let bits = match op {
            BinaryOp::Add => l.bits.wrapping_add(r.bits),
            BinaryOp::Sub => l.bits.wrapping_sub(r.bits),
            BinaryOp::Mul => l.bits.wrapping_mul(r.bits),
            BinaryOp::Div => l.bits / r.bits,
            _ => l.bits % r.bits,
        };
        return Ok(Value::new(bits, ty));
    }
    let (a, b) = (l.extended() as i128, r.extended() as i128);
    let result = match op {
        BinaryOp::Add => a.checked_add(b),
        BinaryOp::Sub => a.checked_sub(b),
        BinaryOp::Mul => a.checked_mul(b),
        BinaryOp::Div => a.checked_div(b),
        _ => a.checked_rem(b),
    };
    match result {
        Some(result) => checked_signed(result, ty, "arithmetic"),
        None => undefined(format!("{op:?} overflows {ty:?}")),
    }
}

/// 6.5.7: the result has the promoted left operand's type.
fn shift(op: BinaryOp, left: Value, count: Value) -> Eval<Value> {
    let ty = left.ty;
    let Some(count) = count.integer() else {
        return undefined("shift count out of range");
    };
    if count < 0 || count >= i128::from(ty.bits) {
        return undefined(format!("shift of {ty:?} by {count}"));
    }
    let count = count as u32;
    match op {
        BinaryOp::Shl if ty.signed => {
            let Some(value) = left.integer().filter(|value| *value >= 0) else {
                return undefined("left shift of a negative value");
            };
            match value.checked_mul(1i128 << count) {
                Some(result) => checked_signed(result, ty, "left shift"),
                None => undefined("left shift overflows i128"),
            }
        }
        BinaryOp::Shl => Ok(Value::new(left.bits << count, ty)),
        // A signed right shift of a negative value is implementation-defined;
        // GCC and Clang shift arithmetically.
        _ => Ok(Value::new(
            match left.integer() {
                Some(value) if ty.signed => (value >> count) as u128,
                _ => left.bits >> count,
            },
            ty,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(bits: u32) -> CType {
        CType::uint(bits)
    }

    fn eval(expr: &CExpr) -> Eval<Value> {
        let symbols = SymbolTable::new();
        Interpreter::new(&symbols).expr(expr)
    }

    /// The rules this module states, on the cases that motivated it.
    #[test]
    fn a_narrow_operand_is_promoted_before_its_operator() {
        // `~(uint8_t)0` is the `int` -1, which widens to all ones.
        let complement = CExpr::unary(UnaryOp::BitNot, CExpr::cast(u(8), CExpr::UIntLit(0)));
        assert_eq!(eval(&complement), Ok(Value::new(u128::MAX, IntType::INT)));
        assert_eq!(
            eval(&CExpr::cast(u(64), complement)),
            Ok(Value::new(u128::from(u64::MAX), IntType::unsigned(64)))
        );
        // `(uint8_t)-1` is the byte's maximum at every width it widens to.
        let ones = CExpr::cast(u(64), CExpr::cast(u(8), CExpr::IntLit(-1)));
        assert_eq!(eval(&ones), Ok(Value::new(0xff, IntType::unsigned(64))));
        // A `uint16_t` times a `uint16_t` is an `int` product, and it
        // overflows.
        let square = CExpr::binary(
            BinaryOp::Mul,
            CExpr::cast(u(16), CExpr::UIntLit(0xffff)),
            CExpr::cast(u(16), CExpr::UIntLit(0xffff)),
        );
        assert!(matches!(eval(&square), Err(Stop::Undefined(_))));
        // A shift by the width is undefined, whatever the machine does.
        let wide = CExpr::binary(
            BinaryOp::Shr,
            CExpr::cast(u(32), CExpr::UIntLit(1)),
            CExpr::IntLit(32),
        );
        assert!(matches!(eval(&wide), Err(Stop::Undefined(_))));
        // A literal the emitter prints as `-0x100` is the `int` -256.
        assert_eq!(
            eval(&CExpr::UIntLit(0xffff_ffff_ffff_ff00)),
            Ok(Value::new((-256i128) as u128, IntType::INT))
        );
    }
}
