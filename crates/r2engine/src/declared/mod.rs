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

mod frame;
mod graph;
mod member;

pub(crate) use frame::rebased;
use graph::Interned;

use r2abi::{Arrival, CDataModel, Prototype, ScalarKind, Type, TypeGraph, TypeId};
use r2source::native::NativeMachine;
use r2source::{
    CanonicalStorageId, SourceFunctionReturn, SourceLogicalValue, SourceParameterLocation,
};
use r2ssa::place::ParamClass;

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
    /// The contract of each call through a typed member, minted from a first seal (S32).
    pub(crate) member_calls: Vec<r2source::SourceCallSiteInterface>,
}

/// The target's C data model, or the Unix one at its pointer width where none is listed.
fn model_of(target: &NativeTarget<'_>) -> CDataModel {
    (target.data_model.copied()).unwrap_or(CDataModel::unix(crate::engine_effective_ptr_bits(
        target.arch,
    )))
}

/// Debug information's types for data objects, as one graph and a node per object.
pub(crate) fn object_types(
    target: &NativeTarget<'_>,
    types: &[Option<TypeId>],
) -> (Vec<Option<u32>>, Option<r2source::SourceTypeGraph>) {
    let mut interned = Interned::new(target.declarations.graph(), model_of(target));
    let nodes = (types.iter())
        .map(|ty| ty.and_then(|ty| interned.node(ty)))
        .collect::<Vec<_>>();
    match nodes.iter().any(Option::is_some) {
        true => (nodes, interned.finish()),
        false => (nodes, None),
    }
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
            model: model_of(target),
        }
    }

    /// The declaration's types interned apart from any interface's graph, whose node order
    /// classifying must not move.
    fn types<'g>(&self, declared: Declared<'g>) -> Interned<'g> {
        Interned::new(declared.graph, self.model)
    }

    /// Each parameter's class, read from `types` in declaration order. O(types reached).
    fn classes(declared: Declared<'_>, types: &mut Interned<'_>) -> Vec<ParamClass> {
        (declared.prototype.parameters.iter())
            .map(|parameter| types.class(parameter.ty))
            .collect()
    }

    /// Where each declared parameter arrives, up to the first class no location takes.
    pub(crate) fn placement(&self, declared: Declared<'_>) -> r2ssa::place::Placement {
        let classes = Self::classes(declared, &mut self.types(declared));
        r2ssa::place::place(&self.target.convention, &classes)
    }

    /// The register each placed parameter arrives in; `None` for one on the stack.
    pub(crate) fn registers(&self, declared: Declared<'_>) -> Vec<Option<CanonicalStorageId>> {
        if self.leading_unstated(declared).is_some() {
            return Vec::new();
        }
        (self.placement(declared).locations.iter())
            .map(|location| location.register())
            .collect()
    }

    /// A declaration placed for the body it describes, or `None` where it is not this body's.
    fn declared_placement(
        &self,
        declared: Declared<'_>,
        types: &mut Interned<'_>,
    ) -> Option<r2ssa::place::Placement> {
        if let Some(why) = self.leading_unstated(declared) {
            r2il::refusal_evidence!("declared-interface", "{}: {why}", declared.prototype.name);
            return None;
        }
        let prototype = declared.prototype;
        let classes = Self::classes(declared, types);
        let arrivals = (prototype.parameters.iter())
            .map(|parameter| match parameter.arrival? {
                Arrival::Unpassed => Some(r2ssa::place::Arrival::Unpassed),
                Arrival::Register(number) => (self.target.dwarf.name_of(number))
                    .and_then(|name| storage(self.target.arch, name).ok())
                    .map(r2ssa::place::Arrival::Register),
            })
            .collect::<Vec<_>>();
        let placed = r2ssa::place::place_declared(
            &self.target.convention,
            &classes,
            &arrivals,
            matches!(
                prototype.convention,
                r2abi::StatedConvention::NoCall | r2abi::StatedConvention::Program
            ),
        );
        match placed {
            Ok(placement) => {
                if let Some(class) = placement.floor {
                    r2il::refusal_evidence!(
                        "declared-interface",
                        "{}: parameter {} has no location ({class:?}); the prefix stays placed",
                        prototype.name,
                        placement.locations.len()
                    );
                }
                Some(placement)
            }
            Err(r2ssa::place::PlacementRefusal::NoCall) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{}: {:?}, so no convention places its parameters",
                    prototype.name,
                    prototype.convention
                );
                None
            }
            Err(r2ssa::place::PlacementRefusal::Arrival(index)) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{}: parameter {index} does not arrive where the declaration places it, so \
                     the body is a specialisation the prototype does not describe",
                    prototype.name
                );
                None
            }
        }
    }

    /// Why a row's first location may hold an argument it does not state (a VTT, or a hidden result
    /// pointer in an argument register), so nothing is placed (call-boundary ADR, S13 as built).
    fn leading_unstated(&self, declared: Declared<'_>) -> Option<&'static str> {
        use r2abi::Passing;
        match declared.row?.passing {
            Passing::Stated => None,
            Passing::VttUnstated => Some("a base-object constructor or destructor may take a VTT"),
            Passing::HiddenResultUnstated => self.hidden_result_in_argument().then_some(
                "no result is stated, and one returned in memory passes a pointer in the \
                 first argument register",
            ),
        }
    }

    /// The hidden result pointer may arrive in an argument register: the convention states no
    /// register for it, or one that overlaps an argument register.
    fn hidden_result_in_argument(&self) -> bool {
        let convention = &self.target.convention;
        let Some(hidden) = convention.hidden_return else {
            return true;
        };
        let arguments = convention.sections.iter().flat_map(|s| s.locations.iter());
        let mut registers = arguments.filter_map(|location| match location {
            r2source::convention::Location::Register { storage, .. } => Some(storage),
            _ => None,
        });
        registers.any(|storage| {
            storage.space == hidden.space
                && storage.offset + u64::from(storage.size) > hidden.offset
                && hidden.offset + u64::from(hidden.size) > storage.offset
        })
    }

    /// Where the result arrives: where its own class arrives. A machine with
    /// separate floating-point registers returns a `double` in one of those.
    /// A result whose class this does not decide is not claimed at all.
    fn result(
        &self,
        declared: Declared<'_>,
        types: &mut Interned<'_>,
    ) -> (SourceFunctionReturn, Option<CanonicalStorageId>) {
        if result_unstated(declared) {
            return (SourceFunctionReturn::Unproven, None);
        }
        let returns = declared.prototype.return_type;
        if declared.graph.peel(returns).0 == TypeId::VOID {
            return (SourceFunctionReturn::Void, None);
        }
        let storage = match types.class(returns) {
            ParamClass::Float(bytes) => {
                (self.machine.conventions.own.results().float).map(|slot| CanonicalStorageId {
                    size: u32::from(bytes).min(slot.size),
                    ..slot
                })
            }
            ParamClass::Integer(_) => self.machine.conventions.own.result(),
            ParamClass::Unplaced(class) => {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{} returns `{}`: no register class ({class:?})",
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

    /// Registers a call to this import may read: its fixed locations, plus every other argument
    /// register under any tail but `None` (Apple arm64 passes `...` on the stack). O(locations).
    pub(crate) fn reads(&self, declared: Declared<'_>) -> r2ssa::call_reads::CallReads {
        let unstated = self.leading_unstated(declared).is_some();
        let placement = self.placement(declared);
        let placed_whole = !unstated && placement.is_whole();
        let mut registers = (placement.locations.iter())
            .filter(|_| !unstated)
            .filter_map(|location| location.register())
            .collect::<Vec<_>>();
        let tail = match self.leading_unstated(declared) {
            Some(_) => r2abi::Tail::Unstated,
            None => declared.row.map_or(r2abi::Tail::Unstated, |row| row.tail),
        };
        let forms = &self.target.convention.forms;
        let on_stack = forms.variadic_on_stack
            && matches!(
                tail,
                r2abi::Tail::Variadic | r2abi::Tail::Format { .. } | r2abi::Tail::Flagged { .. }
            );
        if placed_whole && (tail == r2abi::Tail::None || on_stack) {
            return r2ssa::call_reads::CallReads::placed(registers, None, None, true);
        }
        let overlaps = |a: &CanonicalStorageId, b: &CanonicalStorageId| {
            a.space == b.space
                && a.offset < b.offset + u64::from(b.size)
                && b.offset < a.offset + u64::from(a.size)
        };
        let fixed = registers.len();
        let sections = self.target.convention.sections.iter();
        for location in sections.flat_map(|section| section.locations.iter()) {
            if let r2source::convention::Location::Register { storage, .. } = location
                && !registers.iter().any(|read| overlaps(read, storage))
            {
                registers.push(*storage);
            }
        }
        // A printf format states whether any operand is floating; `al` counts them where it exists.
        let format = match (tail, forms.count_register, placed_whole) {
            (
                r2abi::Tail::Format {
                    index,
                    kind: r2abi::FormatKind::Printf,
                },
                None,
                true,
            ) => {
                let at = placement.locations.get(usize::from(index));
                let floats = self
                    .machine
                    .conventions
                    .own
                    .arguments(r2source::convention::SlotClass::Float);
                (at.and_then(|location| location.register())).map(|format| {
                    r2ssa::call_reads::FormatTail {
                        format,
                        floats: (registers[fixed..].iter())
                            .filter(|read| floats.iter().any(|float| overlaps(read, float)))
                            .copied()
                            .collect(),
                    }
                })
            }
            _ => None,
        };
        r2ssa::call_reads::CallReads::placed(registers, forms.count_register, format, false)
    }

    /// Where a declaration says it takes a pointer.
    pub(crate) fn pointers(&self, declared: Declared<'_>) -> Vec<CanonicalStorageId> {
        let placed = self.registers(declared);
        (declared.prototype.parameters.iter())
            .zip(placed)
            .filter(|(parameter, _)| {
                matches!(
                    declared.graph.resolved(parameter.ty),
                    Some(Type::Pointer { .. })
                )
            })
            .filter_map(|(_, storage)| storage)
            .collect()
    }

    /// A declared prototype as the type layer states it. A parameter with no place, or a result
    /// the row does not state (D330), is `Unknown`; a stated result with no place states nothing.
    pub(crate) fn function_type(&self, declared: Declared<'_>) -> Option<r2types::FunctionType> {
        let mut interned = Interned::new(declared.graph, self.model);
        let params = (declared.prototype.parameters.iter())
            .map(|parameter| interned.declared(parameter.ty))
            .collect::<Vec<_>>();
        let returns = interned.declared(declared.prototype.return_type);
        let graph = interned.finish()?;
        let convert = |id: Option<u32>| {
            id.and_then(|id| r2types::source_type_like(&graph, id))
                .unwrap_or(r2types::CTypeLike::Unknown)
        };
        let params = params.into_iter().map(convert).collect::<Vec<_>>();
        let bases = vec![declared.basis; params.len()];
        let return_type = match result_unstated(declared) {
            true => r2types::CTypeLike::Unknown,
            false => Some(convert(returns)).filter(|ty| *ty != r2types::CTypeLike::Unknown)?,
        };
        Some(r2types::FunctionType {
            return_type,
            params,
            bases,
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
        let mut types = self.types(declared);
        let Some(placement) = self.declared_placement(declared, &mut types) else {
            return Restatement::default();
        };
        let placed = &placement.locations;
        let (returns, result) = self.result(declared, &mut types);
        let mut interned = Interned::new(declared.graph, self.model);
        let parameters = (declared.prototype.parameters.iter())
            .zip(placed)
            .map(|(parameter, location)| interned.value(parameter.ty, carrier_bytes(location)))
            .collect::<Vec<_>>();
        let return_value =
            result.and_then(|slot| interned.value(declared.prototype.return_type, slot.size));
        let registers = placed.iter().map(|location| location.register());
        let mut frame = match with_frame {
            true => self.frame(
                declared,
                &registers.collect::<Vec<_>>(),
                &parameters,
                &mut interned,
            ),
            false => frame::DeclaredFrame::default(),
        };
        let stack_pointer = self.machine.roles.stack_pointer_storage();
        for (index, (location, value)) in placed.iter().zip(&parameters).enumerate() {
            let (
                SourceParameterLocation::Stack {
                    offset, size_bytes, ..
                },
                Some(sp),
            ) = (location, stack_pointer)
            else {
                continue;
            };
            let base = r2source::StackAddressBase::StackPointer;
            let slot = r2source::SourceStackSlotSpec::new_parameter(
                base,
                sp,
                *offset,
                *size_bytes,
                index as u32,
            );
            frame.slots.push(match value {
                Some(value) => slot.with_logical_type(value.type_id()),
                None => slot,
            });
        }
        let typed = Typed {
            basis: declared.basis,
            parameters,
            returns,
            return_value,
            slots: frame.slots.clone(),
            graph: interned.finish(),
        };
        let interface = self.interface(declared, &placement, typed, &frame);
        Restatement {
            signature: interface
                .is_some()
                .then(|| presentation(declared.prototype, placed.len())),
            slot_names: frame.names,
            interface,
            member_calls: Vec::new(),
        }
    }

    fn interface(
        &self,
        declared: Declared<'_>,
        placement: &r2ssa::place::Placement,
        typed: Typed,
        frame: &frame::DeclaredFrame,
    ) -> Option<r2source::SourceFunctionInterface> {
        let name = &declared.prototype.name;
        let convention = self.machine.conventions.own.id;
        let interface = self.typed(name, convention, placement, typed)?;
        // Typed first: a declared format parameter is believed on what the
        // declaration's types are.
        let interface = formatted(
            declared,
            interface.with_types(r2source::Confidence::of(declared.basis)),
        )?;
        let interface = self.flagged(declared, interface);
        let stacked = placement.locations.iter().any(|at| at.register().is_none());
        let interface = match result_unstated(declared) {
            true => self.unstated_result(interface),
            false => interface,
        };
        let interface = self.carriers(name, interface, frame.frame_pointer)?;
        self.stacked_return(name, interface, stacked)
    }

    /// A row whose library body reads its tail under a test of a flag argument, counted where this
    /// target's header states the flag's bits (`Tail::Flagged`); otherwise the tail stays `...`.
    fn flagged(
        &self,
        declared: Declared<'_>,
        interface: r2source::SourceFunctionInterface,
    ) -> r2source::SourceFunctionInterface {
        let Some(r2abi::Tail::Flagged { index, test, then }) = declared.row.map(|row| row.tail)
        else {
            return interface;
        };
        let name = &declared.prototype.name;
        let Some(bits) = self.target.imports.flag_bits(test) else {
            r2il::refusal_evidence!(
                "declared-interface",
                "{name}: no header states {test:?} here"
            );
            return interface;
        };
        let count = r2source::SourceTailCount {
            parameter_index: u32::from(index),
            rule: r2source::SourceTailRule::Flagged {
                any: bits.any,
                all: bits.all,
                then,
            },
        };
        (interface.clone().with_tail_count(count))
            .inspect_err(|error| {
                r2il::refusal_evidence!("declared-interface", "{name}: {error:?}");
            })
            .unwrap_or(interface)
    }

    /// One declaration's placement and types as an exact interface, with the floor where a class
    /// has no location.
    fn typed(
        &self,
        name: &str,
        convention: r2source::ConventionId,
        placement: &r2ssa::place::Placement,
        typed: Typed,
    ) -> Option<r2source::SourceFunctionInterface> {
        let basis = typed.basis;
        let slots = placement.locations.iter().zip(&placement.slots);
        let parameters = slots.enumerate().map(|(index, (location, (id, class)))| {
            let slot = r2source::SourceSlot {
                id: id.0,
                class: *class,
                basis,
            };
            r2source::SourceAbiParameterSpec::with_location(index as u32, *location, slot)
        });
        let revision = format!("declared:{name}").into_bytes();
        let interface = r2source::SourceFunctionInterface::new_exact_with_logical_types(
            revision,
            convention,
            parameters,
            typed.returns,
            typed.slots,
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
        match placement.floor {
            None => Some(interface),
            Some(class) => Some(interface.with_arity_floor(r2source::SourceArityFloor::of([
                r2source::SourceFloorCause::Unplaced(class),
            ])?)),
        }
    }

    /// A result the row does not state: `Unproven({Unstated})`, seeded at the convention's
    /// integer lane; a call states none and leaves every killed lane unproven (D330).
    fn unstated_result(
        &self,
        interface: r2source::SourceFunctionInterface,
    ) -> r2source::SourceFunctionInterface {
        let typed = self.target.convention.typed_results();
        let Some(integer) = typed.integer else {
            return interface;
        };
        let seed = r2source::SourceResultSeed {
            slot: integer,
            bits: integer.size.saturating_mul(8),
            above: r2source::SourceAbove::Undefined,
        };
        let causes = [r2source::SourceResultCause::Unstated];
        let Some(unproven) = r2source::SourceUnprovenResult::of(causes, Some(seed)) else {
            return interface;
        };
        interface.with_unproven_result(unproven)
    }

    /// The return address a call pushes, bound where a stack parameter is placed past it, as the
    /// recovered path binds it; a call site then reads that parameter from its own `[sp]`.
    fn stacked_return(
        &self,
        name: &str,
        interface: r2source::SourceFunctionInterface,
        stacked: bool,
    ) -> Option<r2source::SourceFunctionInterface> {
        let pushed = self
            .target
            .convention
            .owned
            .iter()
            .find_map(|range| match range {
                r2source::convention::OwnedRange::ReturnAddress(at) if at.start == 0 => {
                    u32::try_from(at.end).ok()
                }
                _ => None,
            });
        let (true, Some(bytes)) = (stacked, pushed) else {
            return Some(interface);
        };
        let bound = interface.with_exact_stacked_return(0, bytes, bytes, bytes);
        bound
            .inspect_err(|error| {
                r2il::refusal_evidence!(
                    "declared-interface",
                    "{name}: the pushed return address does not bind: {error:?}"
                );
            })
            .ok()
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
        // The names too: the trusted lift restates each carrier by name, and drops one it cannot name.
        let placed = (interface.with_role_register_names(roles.role_register_names()))
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

/// Whether the declaration is a row that states parameters and no result (a mangled name).
fn result_unstated(declared: Declared<'_>) -> bool {
    declared
        .row
        .is_some_and(|row| row.result == r2abi::RowResult::Unstated)
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
    // The `va_list` parameter a Microsoft x64 home escape is proven a tail by (ADR rule 6).
    let interface = match declared.row.map(|row| row.tail) {
        Some(r2abi::Tail::VaList { index, .. }) => (interface.clone())
            .with_declared_va_list_parameter(u32::from(index))
            .unwrap_or(interface),
        _ => interface,
    };
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

/// The bytes a placed parameter's carrier holds.
fn carrier_bytes(location: &SourceParameterLocation) -> u32 {
    match *location {
        SourceParameterLocation::Register(storage) => storage.size,
        SourceParameterLocation::Stack { size_bytes, .. } => size_bytes,
    }
}

/// The typed half of one declaration: a logical value per parameter, the
/// result's, the frame slots it types, and the graph they are nodes of.
struct Typed {
    /// What every parameter's type rests on: the declaration's basis.
    basis: r2source::Basis,
    parameters: Vec<Option<SourceLogicalValue>>,
    returns: SourceFunctionReturn,
    return_value: Option<SourceLogicalValue>,
    slots: Vec<r2source::SourceStackSlotSpec>,
    graph: Option<r2source::SourceTypeGraph>,
}

/// What a declaration calls a function's parameters; their types travel on the interface's graph.
fn presentation(prototype: &Prototype, placed: usize) -> r2source::SourceSignaturePresentation {
    let parameters = (prototype.parameters.iter())
        .take(placed)
        .map(|parameter| r2source::SourceSignatureParameter::new(parameter.name.clone()));
    let ellipsis =
        (prototype.variadic).then(|| r2source::SourceSignatureParameter::new(Some("...")));
    r2source::SourceSignaturePresentation::new(parameters.chain(ellipsis))
}
