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

use r2abi::{Arrival, DataModel, Prototype, ScalarKind, Type, TypeGraph, TypeId};
use r2source::native::NativeMachine;
use r2source::{CanonicalStorageId, SourceFunctionReturn, SourceLogicalValue};

use crate::native::{NativeTarget, storage};

/// Whether a declared scalar is plain `char`, a type distinct from signed and
/// unsigned char; its kind says whether this ABI makes it signed.
fn is_plain_char(scalar: &r2abi::Scalar, bits: impl Into<u64>) -> bool {
    bits.into() == 8 && scalar.name.as_deref() == Some("char")
}

/// One declaration and the graph its types are nodes of.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Declared<'a> {
    pub(crate) prototype: &'a Prototype,
    pub(crate) graph: &'a TypeGraph,
    /// Which declaration it is: the binary's debug information, or a
    /// library's prototype found by a name.
    pub(crate) basis: r2source::Basis,
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
        })
    }

    /// What the library table declares of an import, by its name.
    pub(crate) fn import(target: &NativeTarget<'a>, name: &str) -> Option<Self> {
        Some(Self {
            prototype: target.prototypes.get(name)?,
            graph: target.prototypes.graph(),
            basis: r2source::Basis::Declared,
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
    pub(crate) model: DataModel,
}

impl<'a> Placement<'a> {
    pub(crate) fn new(target: &'a NativeTarget<'a>, machine: &'a NativeMachine) -> Self {
        Self {
            target,
            machine,
            model: DataModel::unix(crate::engine_effective_ptr_bits(target.arch)),
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
    /// A parameter arrives in the registers its own class uses, and the two
    /// classes are counted separately: the third integer argument takes the
    /// third integer register however many floating-point arguments came
    /// before it. Every parameter before one that cannot be placed is placed
    /// whatever follows it: a seventh argument on the stack does not move the
    /// first six out of their registers.
    pub(crate) fn placed_prefix(&self, declared: Declared<'_>) -> Vec<CanonicalStorageId> {
        let integer_slots = self.machine.slots.argument_slots();
        let (mut integers, mut floats) = (0usize, 0usize);
        let mut placed = Vec::with_capacity(declared.prototype.parameters.len());
        for parameter in &declared.prototype.parameters {
            let slot = match self.class(declared.graph, parameter.ty) {
                Ok(Class::Float(bytes)) => {
                    floats += 1;
                    let slot = self.machine.slots.float_argument_slots().get(floats - 1);
                    slot.map(|slot| self.low_lane(*slot, bytes))
                }
                Ok(Class::Integer) => {
                    integers += 1;
                    integer_slots.get(integers - 1).copied()
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

    /// A declared prototype as the type layer states it, or nothing where a
    /// part of it states nothing the type layer can hold.
    pub(crate) fn function_type(&self, declared: Declared<'_>) -> Option<r2types::FunctionType> {
        let known = |ty: r2types::CTypeLike| (ty != r2types::CTypeLike::Unknown).then_some(ty);
        let params = declared
            .prototype
            .parameters
            .iter()
            .map(|parameter| known(c_type::c_type(declared.graph, parameter.ty, &self.model)))
            .collect::<Option<Vec<_>>>()?;
        Some(r2types::FunctionType {
            return_type: known(c_type::c_type(
                declared.graph,
                declared.prototype.return_type,
                &self.model,
            ))?,
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
        let convention = self.machine.slots.calling_convention();
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
        let interface = variadic(
            declared.prototype,
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

/// A variadic declaration says the call carries a tail past the fixed
/// parameters. Which parameter is the format that counts it is the one the
/// declaration names so: a `char *` called `format` or `fmt`, which is the
/// table's statement and not an inference from the callee's name.
fn variadic(
    prototype: &Prototype,
    interface: r2source::SourceFunctionInterface,
) -> Option<r2source::SourceFunctionInterface> {
    if !prototype.variadic {
        return Some(interface);
    }
    let format = prototype
        .parameters
        .iter()
        .position(|parameter| {
            parameter.name.as_deref().is_some_and(|name| {
                matches!(
                    name.trim_start_matches('_'),
                    "format" | "fmt" | "format_string" | "fmtstr"
                )
            }) && {
                let spelling = parameter.spelling.as_type();
                spelling.contains("char") && spelling.contains('*')
            }
        })
        .and_then(|index| u32::try_from(index).ok());
    interface
        .with_declared_variadic(format)
        .inspect_err(|error| {
            r2il::refusal_evidence!(
                "declared-interface",
                "{} does not state its variadic tail: {error:?}",
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
