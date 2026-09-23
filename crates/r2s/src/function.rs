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
    out.extend(name.map(|name| format!("name: {name}")));
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
        format!("minaddr: {:#010x}", info.min_addr()),
        format!("maxaddr: {:#010x}", info.max_addr()),
        format!("is-lineal: {}", info.is_lineal()),
        format!("end-bbs: {}", info.exits()),
        format!("recursive: {}", info.is_recursive()),
        format!("out-degree: {}", info.direct_calls()),
        format!("locals: {}", info.locals.len()),
        format!("args: {}", info.arguments.len()),
    ]);
    Ok(out.join("\n"))
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

/// `arg <type> argN @ <register>`, numbered from one as radare2 numbers them.
fn spell_argument(session: &Session, entry: u64, argument: &Argument) -> String {
    let at = argument
        .storage
        .and_then(|storage| session.program.spell_storage(entry, storage))
        .map(|register| format!(" @ {register}"))
        .unwrap_or_default();
    format!("arg {} arg{}{at}", argument.ty, argument.slot + 1)
}

/// `var <type> stack_mN @ <base><offset>`, named as the decompiler names it.
fn spell_local(local: &Local) -> String {
    let ty = &local.ty;
    let side = if local.offset < 0 { 'm' } else { 'p' };
    let magnitude = local.offset.unsigned_abs();
    let sign = if local.offset < 0 { '-' } else { '+' };
    // Offsets are from the base at entry, not from the stack pointer where the body runs.
    let base = match local.base {
        r2engine::program::info::StackBase::StackPointer => "entry.sp",
        r2engine::program::info::StackBase::FramePointer => "fp",
        r2engine::program::info::StackBase::Realigned => "realigned.sp",
    };
    format!("var {ty} stack_{side}{magnitude} @ {base}{sign}{magnitude:#x}")
}
