//! What one rendering declares and names, read off the tree it was written from.
//!
//! The emitter writes the C; this says, from the same final tree, which object
//! each declared name is and where in the program each outside name resolves.
//! Nothing here is derived a second time: a variable is a declaration the
//! emitted text contains, its kind and location are the symbol table's role
//! for it, and a link is a declaration or a program object the body names,
//! with the address the lowering resolved it to.

use std::collections::BTreeMap;

use crate::ast::{CExpr, CFunction, CStmt, CType};
use crate::symbol::{ExternalKind, SymbolId, SymbolRole};

/// Which kind of object a declared name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VariableKind {
    /// A parameter of the function.
    Param,
    /// An object the function declares in its body.
    Local,
    /// An object outside every frame the function names.
    Global,
}

/// Where a declared object lives, as far as the rendering knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VariableLocation {
    /// The parameter in this position of the convention's argument slots.
    Argument { slot: u32 },
    /// A frame slot at this offset from the frame base.
    Frame { offset: i64 },
    /// A program object at this address.
    Address(u64),
    /// A value the function computes, held wherever the compiler puts it.
    Carrier,
}

/// One name the rendering declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedVariable {
    pub name: String,
    /// The type it is declared at, as C spells it.
    pub ty: String,
    pub kind: VariableKind,
    pub location: VariableLocation,
}

/// Which kind of thing outside the function a name is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkKind {
    /// A function the program defines.
    Function,
    /// A function the program imports; its address is the stub a call reaches.
    Import,
    /// A data object.
    Object,
    /// A machine operation the specification names, which C cannot state and
    /// no address in the program holds.
    Machine,
}

/// One name outside the function that the rendering refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedLink {
    pub ident: String,
    pub kind: LinkKind,
    /// Where the name resolves in the program, where anything states it.
    pub addr: Option<u64>,
    /// How many bytes the object spans, where its declared type says.
    pub size: Option<u64>,
}

/// Every name the function declares: its parameters in order, then each
/// declaration in the body in the order the text writes it.
pub(crate) fn variables(func: &CFunction) -> Vec<RenderedVariable> {
    let symbols = func.symbols.borrow();
    let entry = |id: SymbolId, ty: &CType, kind: VariableKind| {
        let location = match symbols.get(id).role {
            SymbolRole::Parameter(slot) => VariableLocation::Argument { slot },
            SymbolRole::StackLocal(offset) => VariableLocation::Frame { offset },
            SymbolRole::Carrier | SymbolRole::RenderCursor => VariableLocation::Carrier,
        };
        RenderedVariable {
            name: symbols.name(id).to_string(),
            ty: ty.to_string(),
            kind,
            location,
        }
    };
    let mut found = func
        .params
        .iter()
        .map(|param| entry(param.name, &param.ty, VariableKind::Param))
        .collect::<Vec<_>>();
    found.extend(
        func.locals
            .iter()
            .map(|local| entry(local.name, &local.ty, VariableKind::Local)),
    );
    let mut declared = Vec::new();
    for stmt in &func.body {
        declarations(stmt, &mut declared);
    }
    found.extend(
        declared
            .into_iter()
            .map(|(id, ty)| entry(id, ty, VariableKind::Local)),
    );
    found.extend(
        declared_objects(func).map(|(name, address, ty)| RenderedVariable {
            name: name.to_owned(),
            ty: ty.map_or_else(|| "char[]".to_owned(), ToString::to_string),
            kind: VariableKind::Global,
            location: VariableLocation::Address(address),
        }),
    );
    found
}

/// The declarations in a statement and the statements inside it, in the
/// order the emitter writes them.
fn declarations<'f>(stmt: &'f CStmt, found: &mut Vec<(SymbolId, &'f CType)>) {
    match stmt.unobserved() {
        CStmt::StructuredRegion { stmt, .. } => declarations(stmt, found),
        CStmt::Decl { ty, name, .. } => found.push((*name, ty)),
        CStmt::Block(body) => body.iter().for_each(|stmt| declarations(stmt, found)),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => {
            declarations(then_body, found);
            if let Some(body) = else_body {
                declarations(body, found);
            }
        }
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => declarations(body, found),
        CStmt::For { init, body, .. } => {
            if let Some(init) = init {
                declarations(init, found);
            }
            declarations(body, found);
        }
        CStmt::Switch { cases, default, .. } => {
            for case in cases {
                case.body.iter().for_each(|stmt| declarations(stmt, found));
            }
            for stmt in default.iter().flatten() {
                declarations(stmt, found);
            }
        }
        _ => {}
    }
}

/// The data objects the rendering declares, as the emitter declares them: a
/// name also declared as a function is that function and not an object.
fn declared_objects(func: &CFunction) -> impl Iterator<Item = (&str, u64, Option<&CType>)> {
    func.extern_objects
        .iter()
        .filter(|object| {
            !func
                .externs
                .iter()
                .any(|declaration| declaration.name == object.name)
        })
        .map(|object| {
            (
                object.name.as_str(),
                object.address,
                object.type_fact.as_ref().map(|fact| &fact.ty),
            )
        })
}

/// Every name outside the function the rendering refers to, by name.
///
/// A declared callee is a function or an import as the calls through it say,
/// and a machine operation when no call names it as either; a declared object
/// and an object the body names by address are objects, sized by their
/// declared type where it has a width.
pub(crate) fn links(func: &CFunction, pointer_bits: u32) -> Vec<RenderedLink> {
    let mut called = BTreeMap::<String, ExternalKind>::new();
    let mut objects = BTreeMap::<String, u64>::new();
    func.visit_body_exprs(&mut |expr| match expr {
        CExpr::External { name, kind } => {
            called.entry(name.clone()).or_insert(*kind);
        }
        CExpr::DataObject { address, name } => {
            objects.entry(name.clone()).or_insert(*address);
        }
        _ => {}
    });
    let mut found = BTreeMap::<String, RenderedLink>::new();
    for declaration in &func.externs {
        let kind = match called.get(&declaration.name) {
            Some(ExternalKind::Import) => LinkKind::Import,
            Some(ExternalKind::Function | ExternalKind::Global) => LinkKind::Function,
            _ if declaration.address.is_some() => LinkKind::Function,
            _ => LinkKind::Machine,
        };
        found.insert(
            declaration.name.clone(),
            RenderedLink {
                ident: declaration.name.clone(),
                kind,
                addr: declaration.address,
                size: None,
            },
        );
    }
    for (name, address, ty) in declared_objects(func) {
        found
            .entry(name.to_owned())
            .or_insert_with(|| RenderedLink {
                ident: name.to_owned(),
                kind: LinkKind::Object,
                addr: Some(address),
                size: ty
                    .and_then(|ty| r2types::declaration_type_width_bits(ty, pointer_bits))
                    .filter(|bits| bits % 8 == 0 && *bits > 0)
                    .map(|bits| u64::from(bits / 8)),
            });
    }
    for (name, address) in objects {
        found.entry(name.clone()).or_insert(RenderedLink {
            ident: name,
            kind: LinkKind::Object,
            addr: Some(address),
            size: None,
        });
    }
    found.into_values().collect()
}
