//! One placement rule for declared, recovered and imported parameters
//! (doc/adr-call-boundary.md, "The function's parameters").

use r2source::convention::{ConventionModel, OwnedRange, SectionClass, SlotClass};
use r2source::{
    CanonicalStorageId, ConventionId, SourceParameterLocation, SourceType, SourceTypeGraph,
    SourceTypeKind, SourceUnplacedClass,
};

/// The class one parameter travels in, as its type states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamClass {
    /// An integer or pointer of this many bytes, no wider than one register.
    Integer(u8),
    /// A `float` or `double` of this many bytes.
    Float(u8),
    /// A class no location takes here; it ends the placed prefix.
    Unplaced(SourceUnplacedClass),
}

impl ParamClass {
    /// The class a value of node `id` travels in, the one classifier of a declared type (S32a);
    /// an integer wider than `pointer_bits` takes no register. O(1).
    pub fn of(graph: &SourceTypeGraph, id: u32, pointer_bits: u32) -> Self {
        let node = usize::try_from(id)
            .ok()
            .and_then(|id| graph.types().get(id));
        node.map_or(Self::Unplaced(SourceUnplacedClass::Unsized), |ty| {
            Self::of_type(ty, pointer_bits)
        })
    }

    /// `of` for a node of a graph still being interned, whose kind and size are already final.
    pub fn of_type(ty: &SourceType, pointer_bits: u32) -> Self {
        let bits = u32::try_from(ty.size_bits()).unwrap_or(u32::MAX);
        let bytes = u8::try_from(bits / 8).unwrap_or(u8::MAX);
        match ty.kind() {
            SourceTypeKind::Float if matches!(bits, 32 | 64) => Self::Float(bytes),
            SourceTypeKind::Float => Self::Unplaced(SourceUnplacedClass::Float(bits)),
            SourceTypeKind::SignedInteger
            | SourceTypeKind::UnsignedInteger
            | SourceTypeKind::Char { .. }
            | SourceTypeKind::Pointer { .. } => match bits {
                0 => Self::Unplaced(SourceUnplacedClass::Unsized),
                bits if bits <= pointer_bits => Self::Integer(bytes),
                bits => Self::Unplaced(SourceUnplacedClass::WideInteger(bits)),
            },
            SourceTypeKind::Struct { .. }
            | SourceTypeKind::Union { .. }
            | SourceTypeKind::Array { .. } => Self::Unplaced(SourceUnplacedClass::Aggregate),
            SourceTypeKind::Void | SourceTypeKind::Code { .. } | SourceTypeKind::Opaque { .. } => {
                Self::Unplaced(SourceUnplacedClass::Unsized)
            }
        }
    }
}

/// Where the parameters arrive: the placed prefix, and why the rest have no location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub locations: Vec<SourceParameterLocation>,
    /// The class at `locations.len()` that no location takes.
    pub floor: Option<SourceUnplacedClass>,
}

impl Placement {
    pub fn is_whole(&self) -> bool {
        self.floor.is_none()
    }
}

/// Where a declaration says one parameter is at the first instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    Register(CanonicalStorageId),
    /// Passed nowhere: a clone folded it in.
    Unpassed,
}

/// Why a declaration is no interface of this body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// `DW_CC_nocall`: the compiler chose its own convention.
    NoCall,
    /// The parameter at this index arrives elsewhere (`.isra`, `.constprop`).
    Arrival(usize),
}

/// Each class takes the next location of its own section, or of its position where positions
/// are shared, then the next stack slot past the registers. O(classes + locations).
pub fn place(model: &ConventionModel, classes: &[ParamClass]) -> Placement {
    let registers = |of: SlotClass| model.argument_registers(of).collect::<Vec<_>>();
    let (integers, floats) = (registers(SlotClass::Integer), registers(SlotClass::Float));
    let shared = model.shares_positions();
    // The stack section counts from the call; a parameter is placed from the entry, past the
    // return address a call pushes.
    let pushed = model.owned.iter().find_map(|range| match range {
        OwnedRange::ReturnAddress(at) => Some(at.end - at.start),
        _ => None,
    });
    let stack = model
        .sections
        .iter()
        .find_map(|section| match section.class {
            SectionClass::Stack { first, step } if step > 0 => {
                Some((first + pushed.unwrap_or(0), step))
            }
            _ => None,
        });
    let (mut taken_integers, mut taken_floats, mut stack_bytes) = (0usize, 0usize, 0u32);
    let mut placement = Placement {
        locations: Vec::with_capacity(classes.len()),
        floor: None,
    };
    for (position, class) in classes.iter().enumerate() {
        let (pool, taken, bytes) = match *class {
            ParamClass::Integer(bytes) => (&integers, &mut taken_integers, bytes),
            ParamClass::Float(bytes) => (&floats, &mut taken_floats, bytes),
            ParamClass::Unplaced(why) => {
                placement.floor = Some(why);
                return placement;
            }
        };
        let index = if shared { position } else { *taken };
        *taken += 1;
        if let Some(register) = pool.get(index) {
            let lane = match class {
                ParamClass::Float(_) => low_lane(*register, u32::from(bytes)),
                _ => *register,
            };
            placement
                .locations
                .push(SourceParameterLocation::Register(lane));
            continue;
        }
        let Some((first, step)) = stack else {
            placement.floor = Some(SourceUnplacedClass::Unsized);
            return placement;
        };
        // Apple arm64 packs stack arguments by their size (Apple's arm64 ABI, "Pass arguments").
        if model.id == ConventionId::AppleArm64 && u32::from(bytes) < step {
            placement.floor = Some(SourceUnplacedClass::PackedStack);
            return placement;
        }
        let offset = first + i64::from(stack_bytes);
        stack_bytes += u32::from(bytes).div_ceil(step) * step;
        placement.locations.push(SourceParameterLocation::Stack {
            offset,
            size_bytes: u32::from(bytes),
            callee_offset: offset,
        });
    }
    placement
}

/// A float narrower than its register takes its low bytes, as a Sleigh pentry places it; the
/// graded register files number lanes from the low byte.
fn low_lane(register: CanonicalStorageId, bytes: u32) -> CanonicalStorageId {
    CanonicalStorageId {
        size: bytes.min(register.size),
        ..register
    }
}

/// A declaration placed for the body it describes: refused under `DW_CC_nocall`, or where a
/// placed parameter arrives elsewhere than placed (`.isra`, `.constprop`). O(classes).
pub fn place_declared(
    model: &ConventionModel,
    classes: &[ParamClass],
    arrivals: &[Option<Arrival>],
    nocall: bool,
) -> Result<Placement, PlacementRefusal> {
    if nocall {
        return Err(PlacementRefusal::NoCall);
    }
    let placement = place(model, classes);
    for (index, (location, arrival)) in placement.locations.iter().zip(arrivals).enumerate() {
        let held = match (arrival, location) {
            (None, _) => true,
            (Some(Arrival::Unpassed), _) => false,
            (Some(Arrival::Register(arrived)), SourceParameterLocation::Register(placed)) => {
                arrived.offset == placed.offset
            }
            (Some(Arrival::Register(_)), SourceParameterLocation::Stack { .. }) => false,
        };
        if !held {
            return Err(PlacementRefusal::Arrival(index));
        }
    }
    Ok(placement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2source::CanonicalStorageSpace;
    use r2source::convention::Extension;
    use r2source::convention::{BoundaryForms, ConventionParts, Location, Section};

    fn register(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn section(class: SectionClass, of: SlotClass, offsets: &[u64], bytes: u8) -> Section {
        let locations = offsets
            .iter()
            .enumerate()
            .map(|(position, offset)| Location::Register {
                storage: register(*offset, u32::from(bytes)),
                bytes,
                class: of,
                position: position as u16,
                extension: Extension::Unspecified,
            });
        Section {
            class,
            locations: locations.collect(),
        }
    }

    fn sysv() -> ConventionModel {
        ConventionModel::new(ConventionParts {
            id: ConventionId::SysVAmd64,
            sections: Box::new([
                section(
                    SectionClass::Integer,
                    SlotClass::Integer,
                    &[0x38, 0x30, 0x10, 0x8, 0x80, 0x88],
                    8,
                ),
                section(SectionClass::Float, SlotClass::Float, &[0x1200, 0x1240], 16),
                Section {
                    class: SectionClass::Stack { first: 0, step: 8 },
                    locations: Box::default(),
                },
            ]),
            hidden_return: None,
            results: Box::default(),
            results_complete: None,
            owned: Box::new([OwnedRange::ReturnAddress(0..8)]),
            preserved: Box::default(),
            killed: Box::default(),
            likely_trash: Box::default(),
            reserved: Box::default(),
            link: None,
            forms: BoundaryForms {
                frame_pointer: None,
                red_zone: 128,
                save_area: None,
                count_register: None,
                entry_stack: None,
                variadic_on_stack: false,
                guard: None,
                stack_bound: None,
                security_cookie: None,
                linked_guard: None,
            },
            refused: None,
        })
        .expect("a model")
    }

    #[test]
    fn a_seventh_integer_takes_the_first_stack_slot_and_a_float_its_own_register() {
        let mut classes = vec![ParamClass::Integer(8); 6];
        classes.extend([
            ParamClass::Float(8),
            ParamClass::Integer(4),
            ParamClass::Integer(8),
        ]);
        let placed = place(&sysv(), &classes);
        assert!(placed.is_whole());
        assert_eq!(
            placed.locations[6],
            SourceParameterLocation::Register(register(0x1200, 8))
        );
        let stack = |offset, size_bytes| SourceParameterLocation::Stack {
            offset,
            size_bytes,
            callee_offset: offset,
        };
        assert_eq!(placed.locations[7..], [stack(8, 4), stack(16, 8)]);
    }

    #[test]
    fn an_unplaced_class_keeps_the_prefix_and_names_itself() {
        let classes = [
            ParamClass::Integer(8),
            ParamClass::Unplaced(SourceUnplacedClass::Float(80)),
            ParamClass::Integer(8),
        ];
        let placed = place(&sysv(), &classes);
        assert_eq!(placed.locations.len(), 1);
        assert_eq!(placed.floor, Some(SourceUnplacedClass::Float(80)));
    }

    #[test]
    fn a_declaration_arriving_elsewhere_or_nocall_is_refused() {
        let classes = [ParamClass::Integer(8), ParamClass::Integer(8)];
        let elsewhere = [None, Some(Arrival::Register(register(0x10, 8)))];
        assert_eq!(
            place_declared(&sysv(), &classes, &elsewhere, false),
            Err(PlacementRefusal::Arrival(1))
        );
        let unpassed = [Some(Arrival::Unpassed)];
        assert_eq!(
            place_declared(&sysv(), &classes, &unpassed, false),
            Err(PlacementRefusal::Arrival(0))
        );
        assert_eq!(
            place_declared(&sysv(), &classes, &[], true),
            Err(PlacementRefusal::NoCall)
        );
        let held = [Some(Arrival::Register(register(0x38, 4)))];
        assert!(place_declared(&sysv(), &classes, &held, false).is_ok());
    }
}
