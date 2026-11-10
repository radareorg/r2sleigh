//! What a program and its library table declare, placed in this machine.
//!
//! Two sources declare interfaces, and they answer different questions. The
//! binary's own debug information declares the functions it has bodies for,
//! by the address each body begins: two `static` functions of one name are
//! two declarations, and a name never picks one. The library table declares
//! what an import is expected to be, by the name the binary gives it. Both are
//! read into the same declaration model, and a declaration of either kind is
//! placed here the same way: the convention says where each parameter
//! arrives, the declaration says what it is, and the interface carries both.

mod c_type;
mod frame;
mod graph;

pub(crate) use frame::rebased;
use graph::Interned;

use r2abi::{Arrival, CDataModel, Prototype, ScalarKind, Type, TypeGraph, TypeId};
use r2source::native::NativeMachine;
use r2source::{CanonicalStorageId, SourceFunctionReturn, SourceLogicalValue};

use crate::native::{NativeTarget, storage};

/// Plain `char`'s sign, or `None` for any other scalar. A row's `char` takes
/// the target's model; debug information names `char` and states its sign.
fn plain_char(scalar: &r2abi::Scalar, model: &CDataModel) -> Option<Option<bool>> {
    let sign = |kind| match kind {
        Some(ScalarKind::Signed) => Some(true),
        Some(ScalarKind::Unsigned) => Some(false),
        _ => None,
    };
    match scalar.kind {
        ScalarKind::PlainChar => Some(sign(model.plain_char)),
        _ if model.bits(scalar.width) == Some(8) && scalar.name.as_deref() == Some("char") => {
            Some(sign(Some(scalar.kind)))
        }
        _ => None,
    }
}

/// One declaration and the graph its types are nodes of.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Declared<'a> {
    pub(crate) prototype: &'a Prototype,
    pub(crate) graph: &'a TypeGraph,
    /// Which declaration it is: the binary's debug information, or a
    /// library's prototype found by a name.
    pub(crate) basis: r2source::Basis,
    /// The library row an import binds; `None` for the binary's own declaration.
    pub(crate) row: Option<&'a r2abi::LibraryRow>,
}

impl<'a> Declared<'a> {
    /// What the binary's debug information declares of the body at `entry`.
    pub(crate) fn body(target: &NativeTarget<'a>, entry: u64) -> Option<Self> {
        let declarations = target.declarations;
        if declarations.is_contested(entry) {
            r2il::refusal_evidence!(
                "declared-interface",
                "{entry:#x}: folded functions declare this body with different prototypes"
            );
        }
        Some(Self {
            prototype: declarations.function_at(entry)?,
            graph: declarations.graph(),
            basis: r2source::Basis::DebugInfo,
            row: None,
        })
    }

    /// The row an import binds through its version or the one C library its container names.
    pub(crate) fn import(target: &NativeTarget<'a>, name: &str) -> Option<Self> {
        let imports = target.imports;
        let row = imports.row(name)?;
        Some(Self {
            prototype: imports.rows().prototype(row),
            graph: imports.rows().graph(),
            basis: r2source::Basis::Declared,
            row: Some(row),
        })
    }
}

/// What a capture states about the boundary beyond what the bytes say.
///
/// Both halves describe the same declaration -- where each parameter arrives
/// and what it is called -- so they travel together and a capture that has one
/// without the other would render a signature its body was not prepared for.
#[derive(Debug, Clone, Default)]
pub(crate) struct Restatement {
    pub(crate) interface: Option<r2source::SourceFunctionInterface>,
    pub(crate) signature: Option<r2source::SourceSignaturePresentation>,
    pub(crate) slot_names: Vec<r2source::SourceStackSlotName>,
}

/// Which registers a declared value travels in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Integer,
    /// A float of this many bytes.
    Float(u32),
}

/// The machine one declaration is placed in.
pub(crate) struct Placement<'a> {
    pub(crate) target: &'a NativeTarget<'a>,
    pub(crate) machine: &'a NativeMachine,
    pub(crate) model: CDataModel,
}

impl<'a> Placement<'a> {
    pub(crate) fn new(target: &'a NativeTarget<'a>, machine: &'a NativeMachine) -> Self {
        Self {
            target,
            machine,
            model: target.data_model.copied().unwrap_or(CDataModel::unix(
                crate::engine_effective_ptr_bits(target.arch),
            )),
        }
    }

    /// The register class a value of this type travels in, or why none.
    ///
    /// A record's class depends on its members and on the convention's rules
    /// for them; `long double` has a class of its own on every machine here.
    /// Neither is decided here, and a declaration needing one is refused
    /// rather than placed in the next integer register and wrong about every
    /// argument after it.
    fn class(&self, graph: &TypeGraph, ty: TypeId) -> Result<Class, String> {
        let resolved = graph.resolved(ty);
        let scalar_bits = match resolved {
            Some(Type::Scalar(scalar)) => self.model.bits(scalar.width),
            Some(Type::Enum { underlying, .. }) => graph
                .size_bits(*underlying, &self.model)
                .and_then(|bits| u32::try_from(bits).ok()),
            _ => None,
        };
        match (resolved, scalar_bits) {
            (Some(Type::Scalar(scalar)), bits) if scalar.kind == ScalarKind::Float => match bits {
                Some(bits @ (32 | 64)) => Ok(Class::Float(bits / 8)),
                bits => Err(format!("a {bits:?}-bit float's class is the convention's")),
            },
            (Some(Type::Pointer { .. }), _) => Ok(Class::Integer),
            // One integer register holds at most its own width; a wider
            // integer takes two, which is the convention's to place.
            (_, Some(bits)) if bits <= self.model.pointer_bits => Ok(Class::Integer),
            (other, _) => Err(format!("no register class for {other:?}")),
        }
    }

    /// A value narrower than its register takes its low bytes, as a Sleigh pentry places it.
    fn low_lane(&self, slot: CanonicalStorageId, bytes: u32) -> CanonicalStorageId {
        match self.target.arch.memory_endianness {
            r2il::Endianness::Little if bytes < slot.size => CanonicalStorageId {
                size: bytes,
                ..slot
            },
            _ => slot,
        }
    }

    /// Where the declared parameters arrive, up to the first that does not
    /// arrive in a register this can name.
    ///
    /// A parameter takes the next register of its own class, counted per class or, where the
    /// convention shares positions, by its position. A placed prefix stays placed.
    pub(crate) fn placed_prefix(&self, declared: Declared<'_>) -> Vec<CanonicalStorageId> {
        if let Some(why) = self.leading_unstated(declared) {
            r2il::refusal_evidence!("declared-interface", "{}: {why}", declared.prototype.name);
            return Vec::new();
        }
        let slots = &self.machine.slots;
        let shared = slots.shared_positions();
        let index = |position: usize, count: usize| if shared { position } else { count - 1 };
        let (mut integers, mut floats) = (0usize, 0usize);
        let mut placed = Vec::with_capacity(declared.prototype.parameters.len());
        for (position, parameter) in declared.prototype.parameters.iter().enumerate() {
            let slot = match self.class(declared.graph, parameter.ty) {
                Ok(Class::Float(bytes)) => {
                    floats += 1;
                    let slot = slots.float_argument_slots().get(index(position, floats));
                    slot.map(|slot| self.low_lane(*slot, bytes))
                }
                Ok(Class::Integer) => {
                    integers += 1;
                    slots
                        .argument_slots()
                        .get(index(position, integers))
                        .copied()
                }
                Err(reason) => {
                    r2il::refusal_evidence!(
                        "declared-interface",
                        "{}: `{}`: {reason}",
                        declared.prototype.name,
                        parameter.spelling.as_written()
                    );
                    None
                }
            };
            let Some(slot) = slot else {
                break;
            };
            placed.push(slot);
        }
        placed
    }

    /// Why a row's first location may hold an argument it does not state (a VTT, or a hidden result
    /// pointer in an argument register), so nothing is placed (call-boundary ADR, S13 as built).
    fn leading_unstated(&self, declared: Declared<'_>) -> Option<&'static str> {
        use r2abi::Passing;
        match declared.row?.passing {
            Passing::Stated => None,
            Passing::VttUnstated => Some("a base-object constructor or destructor may take a VTT"),
            Passing::HiddenResultUnstated => {
                let convention = &self.target.convention;
                let arguments = convention.sections.iter().flat_map(|s| s.locations.iter());
                let mut registers = arguments.filter_map(|location| match location {
                    r2source::convention::Location::Register { storage, .. } => Some(storage),
                    _ => None,
                });
                let separate = convention.hidden_return.is_some_and(|hidden| {
                    registers.all(|storage| {
                        storage.space != hidden.space
                            || storage.offset + u64::from(storage.size) <= hidden.offset
                            || hidden.offset + u64::from(hidden.size) <= storage.offset
                    })
                });
                (!separate).then_some(
                    "no result is stated, and one returned in memory passes a pointer in the \
                     first argument register",
                )
            }
        }
    }

    /// Where every declared parameter arrives, or nothing where one cannot
    /// be placed.
    pub(crate) fn placed(&self, declared: Declared<'_>) -> Option<Vec<CanonicalStorageId>> {
        let placed = self.placed_prefix(declared);
        (placed.len() == declared.prototype.parameters.len()).then_some(placed)
    }

    /// Where the result arrives: where its own class arrives. A machine with
    /// separate floating-point registers returns a `double` in one of those.
    /// A result whose class this does not decide is not claimed at all.
    fn result(&self, declared: Declared<'_>) -> (SourceFunctionReturn, Option<CanonicalStorageId>) {
        let returns = declared.prototype.return_type;
        if declared.graph.peel(returns).0 == TypeId::VOID {
            return (SourceFunctionReturn::Void, None);
        }
        let storage = match self.class(declared.graph, returns) {
            Ok(Class::Float(bytes)) => self
                .machine
                .slots
                .float_result_slot()
                .map(|slot| self.low_lane(slot, bytes)),
            Ok(Class::Integer) => self.machine.slots.result_slot(),
            Err(reason) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{} returns `{}`: {reason}",
                    declared.prototype.name,
                    declared.prototype.returns.as_written()
                );
                return (SourceFunctionReturn::Unproven, None);
            }
        };
        match storage {
            Some(storage) => (SourceFunctionReturn::Register { storage }, Some(storage)),
            None => (SourceFunctionReturn::Unproven, None),
        }
    }

    /// Whether the body begins where the declaration says its parameters are.
    ///
    /// A compiler's specialisation of a function -- a `.constprop` clone with
    /// a constant folded in, an `.isra` one passing a member for the pointer
    /// to it -- is described against the source's prototype, which is then
    /// not what the body takes. Where the declaration says a parameter is in
    /// another register at the first instruction, or passed nowhere, the
    /// prototype is not this body's interface.
    fn arrivals_hold(&self, declared: Declared<'_>, placed: &[CanonicalStorageId]) -> bool {
        for (index, (parameter, slot)) in
            declared.prototype.parameters.iter().zip(placed).enumerate()
        {
            let held = match parameter.arrival {
                None => true,
                Some(Arrival::Unpassed) => false,
                Some(Arrival::Register(number)) => (self.target.dwarf.name_of(number))
                    .and_then(|name| storage(self.target.arch, name).ok())
                    .is_none_or(|arrived| arrived.offset == slot.offset),
            };
            if !held {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{}: parameter {index} does not arrive where the declaration places it, so \
                     the body is a specialisation the prototype does not describe",
                    declared.prototype.name
                );
                return false;
            }
        }
        true
    }

    /// Registers a call to this import may read: its fixed locations, plus every other argument
    /// register under any tail but `None` (Apple arm64 passes `...` on the stack). O(locations).
    pub(crate) fn reads(&self, declared: Declared<'_>) -> crate::imports::ImportReads {
        let mut registers = self.placed_prefix(declared);
        let placed_whole = registers.len() == declared.prototype.parameters.len();
        let tail = match self.leading_unstated(declared) {
            Some(_) => r2abi::Tail::Unstated,
            None => declared.row.map_or(r2abi::Tail::Unstated, |row| row.tail),
        };
        let forms = &self.target.convention.forms;
        let on_stack = forms.variadic_on_stack
            && matches!(tail, r2abi::Tail::Variadic | r2abi::Tail::Format { .. });
        if placed_whole && (tail == r2abi::Tail::None || on_stack) {
            return crate::imports::ImportReads {
                registers,
                count_register: None,
            };
        }
        let overlaps = |a: &CanonicalStorageId, b: &CanonicalStorageId| {
            a.space == b.space
                && a.offset < b.offset + u64::from(b.size)
                && b.offset < a.offset + u64::from(a.size)
        };
        let sections = self.target.convention.sections.iter();
        for location in sections.flat_map(|section| section.locations.iter()) {
            if let r2source::convention::Location::Register { storage, .. } = location
                && !registers.iter().any(|read| overlaps(read, storage))
            {
                registers.push(*storage);
            }
        }
        crate::imports::ImportReads {
            registers,
            count_register: forms.count_register,
        }
    }

    /// Where a declaration says it takes a pointer.
    pub(crate) fn pointers(&self, declared: Declared<'_>) -> Vec<CanonicalStorageId> {
        let placed = self.placed_prefix(declared);
        declared
            .prototype
            .parameters
            .iter()
            .zip(placed)
            .filter(|(parameter, _)| {
                matches!(
                    declared.graph.resolved(parameter.ty),
                    Some(Type::Pointer { .. })
                )
            })
            .map(|(_, storage)| storage)
            .collect()
    }

    /// A declared prototype as the type layer states it. A parameter whose type the layer cannot
    /// hold is `Unknown` and keeps the rest (D151); a result it cannot hold states nothing.
    pub(crate) fn function_type(&self, declared: Declared<'_>) -> Option<r2types::FunctionType> {
        let convert = |ty| c_type::c_type(declared.graph, ty, &self.model);
        let params = (declared.prototype.parameters.iter())
            .map(|parameter| convert(parameter.ty))
            .collect();
        let return_type = convert(declared.prototype.return_type);
        Some(r2types::FunctionType {
            return_type: (return_type != r2types::CTypeLike::Unknown).then_some(return_type)?,
            params,
            variadic: declared.prototype.variadic,
        })
    }
}

/// Declarations as interfaces.
impl Placement<'_> {
    /// A declaration, placed in this machine's carriers, with the frame it
    /// states where `with_frame` says it has a body here.
    ///
    /// Every item is typed on its own: a parameter or a local whose type has
    /// no place in the interface's graph carries no type, and the others keep
    /// theirs.
    pub(crate) fn restatement(&self, declared: Declared<'_>, with_frame: bool) -> Restatement {
        let Some(placed) = self.placed(declared) else {
            return Restatement::default();
        };
        if !self.arrivals_hold(declared, &placed) {
            return Restatement::default();
        }
        let (returns, result) = self.result(declared);
        let mut interned = Interned::new(declared.graph, self.model);
        let parameters = declared
            .prototype
            .parameters
            .iter()
            .zip(&placed)
            .map(|(parameter, slot)| interned.value(parameter.ty, slot.size))
            .collect::<Vec<_>>();
        let return_value =
            result.and_then(|slot| interned.value(declared.prototype.return_type, slot.size));
        let frame = match with_frame {
            true => self.frame(declared, &placed, &parameters, &mut interned),
            false => frame::DeclaredFrame::default(),
        };
        let typed = Typed {
            parameters,
            returns,
            return_value,
            graph: interned.finish(),
        };
        let interface = self.interface(declared, &placed, typed, &frame);
        Restatement {
            signature: interface
                .is_some()
                .then(|| presentation(declared.prototype)),
            slot_names: frame.names,
            interface,
        }
    }

    fn interface(
        &self,
        declared: Declared<'_>,
        placed: &[CanonicalStorageId],
        typed: Typed,
        frame: &frame::DeclaredFrame,
    ) -> Option<r2source::SourceFunctionInterface> {
        let name = &declared.prototype.name;
        let parameters = placed
            .iter()
            .enumerate()
            .map(|(index, storage)| r2source::SourceAbiParameterSpec::new(index as u32, *storage));
        let revision = format!("declared:{name}").into_bytes();
        let convention = self.machine.slots.convention();
        let interface = r2source::SourceFunctionInterface::new_exact_with_logical_types(
            revision,
            convention,
            parameters,
            typed.returns,
            frame.slots.clone(),
            typed.parameters,
            typed.return_value,
            typed.graph,
        )
        .inspect_err(|error| {
            r2il::refusal_evidence!(
                "declared-interface",
                "{name} does not state an interface: {error:?}"
            );
        })
        .ok()?;
        // Typed first: a declared format parameter is believed on what the
        // declaration's types are.
        let interface = formatted(
            declared,
            interface.with_types(r2source::Confidence::of(declared.basis)),
        )?;
        self.carriers(name, interface, frame.frame_pointer)
    }

    /// The machine's role carriers, on an interface the declaration states.
    fn carriers(
        &self,
        name: &str,
        interface: r2source::SourceFunctionInterface,
        frame_pointer: Option<CanonicalStorageId>,
    ) -> Option<r2source::SourceFunctionInterface> {
        let roles = self.machine.roles;
        let (Some(return_address), Some(stack_pointer)) = (
            roles.return_address_storage(),
            roles.stack_pointer_storage(),
        ) else {
            r2il::refusal_evidence!(
                "declared-interface",
                "{name}: this machine names no return address or stack pointer carrier"
            );
            return None;
        };
        let placed = interface
            .with_return_address_storage(return_address)
            .and_then(|interface| interface.with_stack_pointer_storage(stack_pointer))
            .and_then(|interface| match frame_pointer {
                None => Ok(interface),
                Some(storage) => interface.with_frame_pointer_storage(storage),
            });
        match placed {
            Ok(interface) => Some(interface),
            Err(error) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{name} does not fit this machine's carriers: {error:?}"
                );
                None
            }
        }
    }
}

/// The row's cited format: a `...` counted by `Tail::Format`, or a `va_list` whose format
/// `Tail::VaList` names, through which a caller's body is seen to forward its own format.
fn formatted(
    declared: Declared<'_>,
    interface: r2source::SourceFunctionInterface,
) -> Option<r2source::SourceFunctionInterface> {
    let prototype = declared.prototype;
    let format = (declared.row)
        .and_then(|row| row.tail.printf_format())
        .map(u32::from);
    let stated = match (prototype.variadic, format) {
        (true, format) => interface.with_declared_variadic(format),
        (false, Some(format)) => interface.with_declared_format_parameter(format),
        (false, None) => return Some(interface),
    };
    stated
        .inspect_err(|error| {
            r2il::refusal_evidence!(
                "declared-interface",
                "{} does not state its format or tail: {error:?}",
                prototype.name
            );
        })
        .ok()
}

/// The typed half of one declaration: a logical value per parameter, the
/// result's, and the graph they are nodes of.
struct Typed {
    parameters: Vec<Option<SourceLogicalValue>>,
    returns: SourceFunctionReturn,
    return_value: Option<SourceLogicalValue>,
    graph: Option<r2source::SourceTypeGraph>,
}

/// How a declaration spells a function, for rendering rather than for
/// reading.
///
/// The interface carries the widths; without this the renderer has only
/// those, so a `size_t` arrives as a 64-bit register and is spelled as one.
fn presentation(prototype: &Prototype) -> r2source::SourceSignaturePresentation {
    let parameters = prototype.parameters.iter().map(|parameter| {
        r2source::SourceSignatureParameter::new(
            parameter.name.clone(),
            Some(parameter.spelling.as_written().to_owned()),
        )
    });
    let ellipsis = prototype
        .variadic
        .then(|| r2source::SourceSignatureParameter::new(Some("..."), None::<String>));
    r2source::SourceSignaturePresentation::new(
        Some(prototype.returns.as_written().to_owned()),
        None::<String>,
        false,
        parameters.chain(ellipsis),
    )
}
