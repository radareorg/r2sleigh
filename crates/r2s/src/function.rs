//! `afi` and `afv`: one function, as radare2 lays it out.
//!
//! Every field is one the engine proved; radare2's fields with nothing behind
//! them here are left out, so a diff reports a missing line, not a wrong one.

use r2engine::program::info::{Argument, Local};

use crate::commands::parse_number;
use crate::session::Session;

/// `afi`: what the function is.
pub fn info(session: &mut Session, argument: &str) -> Result<String, String> {
    let entry = parse_number(session, argument)?;
    let info = session.program.function_info(entry)?;
    let name = session
        .program
        .names()
        .of(entry)
        .map(r2engine::names::Name::spelled);
    let mut out = vec!["#".to_owned(), format!("addr: {entry:#010x}")];
    out.extend(name.as_ref().map(|name| format!("name: {name}")));
    out.extend([
        format!("size: {}", info.max_addr() - info.min_addr()),
        format!("realsz: {}", info.real_size()),
    ]);
    out.extend(info.convention.as_ref().map(|cc| format!("callconv: {cc}")));
    out.extend([
        format!("cyclomatic-complexity: {}", info.complexity()),
        format!("num-bbs: {}", info.blocks.len()),
        format!("num-instrs: {}", info.instructions()),
        format!("edges: {}", info.edges()),
    ]);
    out.extend(signature(&info, name.as_deref()));
    out.extend([
        format!("minaddr: {:#010x}", info.min_addr()),
        format!("maxaddr: {:#010x}", info.max_addr()),
        format!("is-lineal: {}", info.is_lineal()),
        format!("end-bbs: {}", info.exits()),
    ]);
    // Only a proof is printed: a function nothing proves never returns may still never return.
    out.extend(info.noreturn.then(|| "noreturn: true".to_owned()));
    out.extend([
        format!("recursive: {}", info.is_recursive()),
        format!("out-degree: {}", info.direct_calls()),
        format!("locals: {}", info.locals.len()),
        format!("args: {}", info.arguments.len()),
    ]);
    Ok(out.join("\n"))
}

/// `signature: <ret> <name> (<type> <arg>, ...);`, as radare2's `afcf` spells one, where it is authorized.
fn signature(info: &r2engine::program::info::FunctionInfo, name: Option<&str>) -> Option<String> {
    // An unproven return is the carrier the rendered header declares, marked
    // as the unproven value it is; with no carrier, the mark alone keeps the
    // arity showing.
    let returns = match (&info.returns, info.return_unproven) {
        (Some(returns), false) => returns.to_string(),
        (Some(carrier), true) => format!("/* unproven */ {carrier}"),
        (None, true) => "/* unproven */".to_owned(),
        (None, false) => return None,
    };
    let parameters = info
        .arguments
        .iter()
        .map(|argument| argument.declared_as(&argument_name(argument)))
        .collect::<Vec<_>>();
    Some(format!(
        "signature: {returns} {} ({});",
        name?,
        parameters.join(", ")
    ))
}

/// What the source calls a parameter, or `argN` numbered from one as radare2 numbers them.
fn argument_name(argument: &Argument) -> String {
    argument
        .name
        .clone()
        .unwrap_or_else(|| format!("arg{}", argument.slot + 1))
}

/// `afv`: the function's arguments, then its locals.
pub fn variables(session: &mut Session, argument: &str) -> Result<String, String> {
    let entry = parse_number(session, argument)?;
    let info = session.program.function_info(entry)?;
    let arguments = info
        .arguments
        .iter()
        .map(|argument| spell_argument(session, entry, argument));
    let locals = info.locals.iter().map(spell_local);
    Ok(arguments.chain(locals).collect::<Vec<_>>().join("\n"))
}

/// `arg <type> <name> @ <register>`.
fn spell_argument(session: &Session, entry: u64, argument: &Argument) -> String {
    let at = argument
        .storage
        .and_then(|storage| session.program.spell_storage(entry, storage))
        .map(|register| format!(" @ {register}"))
        .unwrap_or_default();
    format!("arg {} {}{at}", argument.ty, argument_name(argument))
}

/// `var <type> <name> @ <base><offset>`, named as the decompiler names it.
fn spell_local(local: &Local) -> String {
    let ty = &local.ty;
    let magnitude = local.offset.unsigned_abs();
    let sign = if local.offset < 0 { '-' } else { '+' };
    // Offsets are from the base at entry, not from the stack pointer where the body runs.
    let base = match local.base {
        r2engine::program::info::StackBase::StackPointer => "entry.sp",
        r2engine::program::info::StackBase::FramePointer => "fp",
        r2engine::program::info::StackBase::Realigned => "realigned.sp",
    };
    format!("var {ty} {} @ {base}{sign}{magnitude:#x}", local.name)
}

/// `afb`: the function's basic blocks, one per line in address order, as
/// radare2 lists them: start, end, size, then where control goes -- `j` the
/// jump (or the only way on), `f` the fall-through of a conditional branch,
/// `s` each target of a dispatch. radare2's trace column has nothing behind it
/// statically and is left out.
pub fn blocks(session: &mut Session, argument: &str) -> Result<String, String> {
    use r2engine::program::EdgeKind;
    let entry = parse_number(session, argument)?;
    let graph = session.program.function_graph(entry)?;
    if graph.blocks.is_empty() {
        return Err(format!("no blocks at {entry:#x}"));
    }
    let mut out = String::new();
    for block in &graph.blocks {
        out.push_str(&format!(
            "{:#010x} {:#010x} {}",
            block.address,
            block.address + block.size,
            block.size
        ));
        // radare2 writes the jump before the fall-through, whatever order the walk found them in.
        let mut edges = block.edges.clone();
        edges.sort_by_key(|edge| matches!(edge.kind, EdgeKind::NotTaken));
        for edge in edges {
            let tag = match edge.kind {
                EdgeKind::Jump | EdgeKind::Fall | EdgeKind::Taken => 'j',
                EdgeKind::NotTaken => 'f',
                EdgeKind::Case | EdgeKind::Default => 's',
            };
            out.push_str(&format!(" {tag} {:#010x}", edge.target));
        }
        out.push('\n');
    }
    Ok(out.trim_end().to_owned())
}
