//! r2sleigh CLI - Compile Sleigh specs to r2il
//!
//! Usage:
//!   r2sleigh compile <input.slaspec> -o <output.r2il>
//!   r2sleigh info <input.r2il>
//!   r2sleigh test-arch <arch>
//!   r2sleigh disasm --arch x86-64 --bytes "554889e5"

use clap::{Parser, Subcommand};
use r2il::serialize;
use r2sleigh_lift::{create_arm_spec, create_x86_64_spec, Lifter};
use std::path::PathBuf;

#[cfg(feature = "sleigh-config")]
use r2sleigh_lift::Disassembler;

/// r2sleigh - Sleigh to r2il compiler for radare2
#[derive(Parser)]
#[command(name = "r2sleigh")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a Sleigh specification to r2il binary format
    Compile {
        /// Input Sleigh specification file (.slaspec)
        input: PathBuf,

        /// Output r2il binary file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Architecture variant (e.g., "default", "thumb")
        #[arg(short, long, default_value = "default")]
        variant: String,
    },

    /// Display information about an r2il file
    Info {
        /// Input r2il file
        input: PathBuf,

        /// Show all registers
        #[arg(short, long)]
        registers: bool,

        /// Show all address spaces
        #[arg(short, long)]
        spaces: bool,
    },

    /// Generate a test architecture specification
    TestArch {
        /// Architecture name (x86-64, arm)
        arch: String,

        /// Output r2il binary file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show version and format information
    Version,

    /// Disassemble instruction bytes to r2il
    #[cfg(feature = "sleigh-config")]
    Disasm {
        /// Architecture (e.g., x86-64, ARM)
        #[arg(short, long)]
        arch: String,

        /// Hex-encoded instruction bytes
        #[arg(short, long)]
        bytes: String,

        /// Base address for disassembly
        #[arg(long, default_value = "0x1000")]
        addr: String,

        /// Output format: text, json, or esil
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Compile {
            input,
            output,
            variant,
        } => cmd_compile(&input, output.as_ref(), &variant),

        Commands::Info {
            input,
            registers,
            spaces,
        } => cmd_info(&input, registers, spaces),

        Commands::TestArch { arch, output } => cmd_test_arch(&arch, output.as_ref()),

        Commands::Version => cmd_version(),

        #[cfg(feature = "sleigh-config")]
        Commands::Disasm {
            arch,
            bytes,
            addr,
            format,
        } => cmd_disasm(&arch, &bytes, &addr, &format),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_compile(input: &PathBuf, output: Option<&PathBuf>, _variant: &str) -> Result<(), String> {
    println!("Compiling: {}", input.display());

    // Determine output path
    let output_path = match output {
        Some(p) => p.clone(),
        None => input.with_extension("r2il"),
    };

    // Determine architecture from filename
    let arch_name = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    // Create spec based on architecture detection
    // Note: For raw .slaspec files, use sleigh-compiler to compile first.
    // This command works best with pre-built specs.
    let spec = if arch_name.contains("x86") || arch_name.contains("ia") || arch_name.contains("64") {
        println!("  Detected x86-64 architecture");
        create_x86_64_spec()
    } else if arch_name.to_lowercase().contains("arm") {
        println!("  Detected ARM architecture");
        create_arm_spec()
    } else {
        println!("  Using generic architecture based on filename: {}", arch_name);
        // Create a minimal spec
        let lifter = Lifter::new(arch_name);
        lifter.compile().map_err(|e| e.to_string())?
    };

    // Save the compiled spec
    serialize::save(&spec, &output_path).map_err(|e| e.to_string())?;

    println!("Output: {}", output_path.display());
    println!("  Architecture: {}", spec.name);
    println!("  Registers: {}", spec.registers.len());
    println!("  Spaces: {}", spec.spaces.len());

    // Show file size
    if let Ok(metadata) = std::fs::metadata(&output_path) {
        let size = metadata.len();
        if size >= 1024 * 1024 {
            println!("  Size: {:.2} MB", size as f64 / (1024.0 * 1024.0));
        } else if size >= 1024 {
            println!("  Size: {:.2} KB", size as f64 / 1024.0);
        } else {
            println!("  Size: {} bytes", size);
        }
    }

    Ok(())
}

fn cmd_info(input: &PathBuf, show_registers: bool, show_spaces: bool) -> Result<(), String> {
    let spec = serialize::load(input).map_err(|e| e.to_string())?;

    println!("r2il File: {}", input.display());
    println!("Architecture: {}", spec.name);
    println!("Variant: {}", spec.variant);
    println!("Endianness: {}", if spec.big_endian { "big" } else { "little" });
    println!("Address size: {} bytes", spec.addr_size);
    println!("Alignment: {}", spec.alignment);
    println!("Registers: {}", spec.registers.len());
    println!("Address spaces: {}", spec.spaces.len());
    println!("User operations: {}", spec.userops.len());
    println!("Source files: {}", spec.source_files.len());

    if show_spaces || (!show_registers && !show_spaces) {
        println!("\nAddress Spaces:");
        for space in &spec.spaces {
            println!(
                "  {:12} addr_size={} word_size={} {}",
                space.name,
                space.addr_size,
                space.word_size,
                if space.is_default { "(default)" } else { "" }
            );
        }
    }

    if show_registers {
        println!("\nRegisters:");
        for reg in &spec.registers {
            let parent_str = reg
                .parent
                .as_ref()
                .map(|p| format!(" (sub of {})", p))
                .unwrap_or_default();
            println!(
                "  {:12} offset=0x{:04x} size={}{}",
                reg.name, reg.offset, reg.size, parent_str
            );
        }
    }

    if !spec.userops.is_empty() {
        println!("\nUser Operations:");
        for userop in &spec.userops {
            println!("  {}: {}", userop.index, userop.name);
        }
    }

    if !spec.source_files.is_empty() {
        println!("\nSource Files:");
        for file in &spec.source_files {
            println!("  {}", file);
        }
    }

    Ok(())
}

fn cmd_test_arch(arch: &str, output: Option<&PathBuf>) -> Result<(), String> {
    let spec = match arch.to_lowercase().as_str() {
        "x86-64" | "x86_64" | "x64" | "amd64" => {
            println!("Generating x86-64 test specification...");
            create_x86_64_spec()
        }
        "arm" | "arm32" => {
            println!("Generating ARM test specification...");
            create_arm_spec()
        }
        _ => {
            return Err(format!(
                "Unknown architecture: {}. Supported: x86-64, arm",
                arch
            ));
        }
    };

    let output_path = match output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!("{}.r2il", arch)),
    };

    serialize::save(&spec, &output_path).map_err(|e| e.to_string())?;

    println!("Output: {}", output_path.display());
    println!("  Architecture: {}", spec.name);
    println!("  Registers: {}", spec.registers.len());

    Ok(())
}

fn cmd_version() -> Result<(), String> {
    println!("r2sleigh {}", env!("CARGO_PKG_VERSION"));
    println!("r2il format version: {}", r2il::FORMAT_VERSION);
    println!("Magic bytes: {:?}", std::str::from_utf8(r2il::MAGIC).unwrap_or("R2IL"));

    #[cfg(feature = "sleigh-config")]
    println!("Disasm support: enabled");
    #[cfg(not(feature = "sleigh-config"))]
    println!("Disasm support: disabled (build with --features x86 to enable)");

    Ok(())
}

#[cfg(feature = "sleigh-config")]
fn cmd_disasm(arch: &str, bytes_hex: &str, addr_str: &str, format: &str) -> Result<(), String> {
    // Parse the address
    let addr = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        u64::from_str_radix(&addr_str[2..], 16).map_err(|e| format!("Invalid address: {}", e))?
    } else {
        addr_str.parse::<u64>().map_err(|e| format!("Invalid address: {}", e))?
    };

    // Parse hex bytes
    let bytes = hex::decode(bytes_hex.replace(" ", "").replace("0x", ""))
        .map_err(|e| format!("Invalid hex bytes: {}", e))?;

    if bytes.is_empty() {
        return Err("No bytes provided".to_string());
    }

    // Get the disassembler for the requested architecture
    let disasm = get_disassembler(arch)?;

    // Lift the instruction
    let block = disasm.lift(&bytes, addr).map_err(|e| format!("Lift failed: {}", e))?;

    // Also get the native disassembly for display
    let (mnemonic, size) = disasm.disasm_native(&bytes, addr)
        .map_err(|e| format!("Native disasm failed: {}", e))?;

    match format {
        "json" => {
            // Simple JSON output
            println!("{{");
            println!("  \"addr\": \"0x{:x}\",", block.addr);
            println!("  \"size\": {},", size);
            println!("  \"mnemonic\": \"{}\",", mnemonic);
            println!("  \"ops\": [");
            for (i, op) in block.ops.iter().enumerate() {
                let comma = if i < block.ops.len() - 1 { "," } else { "" };
                println!("    \"{}\"{}", format_op(&disasm, op), comma);
            }
            println!("  ]");
            println!("}}");
        }
        "esil" => {
            // Convert to ESIL-like format (simplified)
            println!("# 0x{:x}: {} (size={})", addr, mnemonic, size);
            for op in &block.ops {
                println!("{}", op_to_esil(&disasm, op));
            }
        }
        _ => {
            // Text format (default)
            println!("0x{:x}  {}  (size={})", addr, mnemonic, size);
            println!("P-code ({} ops):", block.ops.len());
            for (i, op) in block.ops.iter().enumerate() {
                println!("  {}: {}", i, format_op(&disasm, op));
            }
        }
    }

    Ok(())
}

/// Format an R2ILOp with resolved register names
#[cfg(feature = "sleigh-config")]
fn format_op(disasm: &Disassembler, op: &r2il::R2ILOp) -> String {
    use r2il::R2ILOp::*;

    match op {
        Copy { dst, src } => format!(
            "Copy {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        Load { dst, space, addr } => format!(
            "Load {{ dst: {}, space: {:?}, addr: {} }}",
            disasm.format_varnode(dst),
            space,
            disasm.format_varnode(addr)
        ),
        Store { space, addr, val } => format!(
            "Store {{ space: {:?}, addr: {}, val: {} }}",
            space,
            disasm.format_varnode(addr),
            disasm.format_varnode(val)
        ),
        IntAdd { dst, a, b } => format!(
            "IntAdd {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSub { dst, a, b } => format!(
            "IntSub {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntAnd { dst, a, b } => format!(
            "IntAnd {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntOr { dst, a, b } => format!(
            "IntOr {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntXor { dst, a, b } => format!(
            "IntXor {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntEqual { dst, a, b } => format!(
            "IntEqual {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSLess { dst, a, b } => format!(
            "IntSLess {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntCarry { dst, a, b } => format!(
            "IntCarry {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntSCarry { dst, a, b } => format!(
            "IntSCarry {{ dst: {}, a: {}, b: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(a),
            disasm.format_varnode(b)
        ),
        IntZExt { dst, src } => format!(
            "IntZExt {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        PopCount { dst, src } => format!(
            "PopCount {{ dst: {}, src: {} }}",
            disasm.format_varnode(dst),
            disasm.format_varnode(src)
        ),
        Branch { target } => format!("Branch {{ target: {} }}", disasm.format_varnode(target)),
        CBranch { cond, target } => format!(
            "CBranch {{ cond: {}, target: {} }}",
            disasm.format_varnode(cond),
            disasm.format_varnode(target)
        ),
        Call { target } => format!("Call {{ target: {} }}", disasm.format_varnode(target)),
        Return { target } => format!("Return {{ target: {} }}", disasm.format_varnode(target)),
        _ => format!("{:?}", op),
    }
}

/// Convert an R2ILOp to radare2 ESIL string.
///
/// ESIL (Evaluable Strings Intermediate Language) uses reverse Polish notation:
/// - `a,b,+` = a + b
/// - `a,b,=` = b = a (assignment)
/// - `a,[N]` = read N bytes from address a
/// - `a,b,=[N]` = write N bytes of b to address a
#[cfg(feature = "sleigh-config")]
fn op_to_esil(disasm: &Disassembler, op: &r2il::R2ILOp) -> String {
    use r2il::R2ILOp::*;

    // Helper to format varnode as lowercase ESIL operand
    let vn = |v: &r2il::Varnode| disasm.format_varnode(v).to_lowercase();

    // Helper to get size suffix for memory operations
    let size_suffix = |size: u32| -> String {
        match size {
            1 => "[1]".to_string(),
            2 => "[2]".to_string(),
            4 => "[4]".to_string(),
            8 => "[8]".to_string(),
            _ => format!("[{}]", size),
        }
    };

    match op {
        // ========== Data Movement ==========
        Copy { dst, src } => format!("{},{},=", vn(src), vn(dst)),

        Load { dst, addr, .. } => {
            let sz = size_suffix(dst.size);
            format!("{},{},{},=", vn(addr), sz, vn(dst))
        }

        Store { addr, val, .. } => {
            let sz = size_suffix(val.size);
            format!("{},{},={}", vn(val), vn(addr), sz)
        }

        // ========== Integer Arithmetic ==========
        IntAdd { dst, a, b } => format!("{},{},+,{},=", vn(a), vn(b), vn(dst)),
        IntSub { dst, a, b } => format!("{},{},-,{},=", vn(a), vn(b), vn(dst)),
        IntMult { dst, a, b } => format!("{},{},*,{},=", vn(a), vn(b), vn(dst)),
        IntDiv { dst, a, b } => format!("{},{},/,{},=", vn(a), vn(b), vn(dst)),
        IntSDiv { dst, a, b } => format!("{},{},~/,{},=", vn(a), vn(b), vn(dst)),
        IntRem { dst, a, b } => format!("{},{},%,{},=", vn(a), vn(b), vn(dst)),
        IntSRem { dst, a, b } => format!("{},{},~%,{},=", vn(a), vn(b), vn(dst)),
        IntNegate { dst, src } => format!("{},0,-,{},=", vn(src), vn(dst)),

        // Carry/borrow operations (set flags)
        IntCarry { dst, a, b } => format!("{},{},+,$c,{},=", vn(a), vn(b), vn(dst)),
        IntSCarry { dst, a, b } => format!("{},{},+,$o,{},=", vn(a), vn(b), vn(dst)),
        IntSBorrow { dst, a, b } => format!("{},{},-,$b,{},=", vn(a), vn(b), vn(dst)),

        // ========== Logical Operations ==========
        IntAnd { dst, a, b } => format!("{},{},&,{},=", vn(a), vn(b), vn(dst)),
        IntOr { dst, a, b } => format!("{},{},|,{},=", vn(a), vn(b), vn(dst)),
        IntXor { dst, a, b } => format!("{},{},^,{},=", vn(a), vn(b), vn(dst)),
        IntNot { dst, src } => format!("{},~,{},=", vn(src), vn(dst)),

        // ========== Shift Operations ==========
        IntLeft { dst, a, b } => format!("{},{},<<,{},=", vn(a), vn(b), vn(dst)),
        IntRight { dst, a, b } => format!("{},{},>>,{},=", vn(a), vn(b), vn(dst)),
        IntSRight { dst, a, b } => format!("{},{},>>>,{},=", vn(a), vn(b), vn(dst)),

        // ========== Comparison Operations ==========
        IntEqual { dst, a, b } => format!("{},{},==,{},=", vn(a), vn(b), vn(dst)),
        IntNotEqual { dst, a, b } => format!("{},{},==,!,{},=", vn(a), vn(b), vn(dst)),
        IntLess { dst, a, b } => format!("{},{},<,{},=", vn(a), vn(b), vn(dst)),
        IntSLess { dst, a, b } => format!("{},{},<$,{},=", vn(a), vn(b), vn(dst)),
        IntLessEqual { dst, a, b } => format!("{},{},<=,{},=", vn(a), vn(b), vn(dst)),
        IntSLessEqual { dst, a, b } => format!("{},{},<=$,{},=", vn(a), vn(b), vn(dst)),

        // ========== Extension Operations ==========
        // Zero/sign extension - in ESIL, size is implicit in destination
        IntZExt { dst, src } => format!("{},{},=", vn(src), vn(dst)),
        IntSExt { dst, src } => {
            // Sign extension: use ~~ operator (value,bits,~~)
            // This sign-extends from src_bits to full register width
            let src_bits = src.size * 8;
            format!("{},{},~~,{},=", vn(src), src_bits, vn(dst))
        }

        // ========== Boolean Operations ==========
        BoolNot { dst, src } => format!("{},!,{},=", vn(src), vn(dst)),
        BoolAnd { dst, a, b } => format!("{},{},&&,{},=", vn(a), vn(b), vn(dst)),
        BoolOr { dst, a, b } => format!("{},{},||,{},=", vn(a), vn(b), vn(dst)),
        BoolXor { dst, a, b } => format!("{},{},^^,{},=", vn(a), vn(b), vn(dst)),

        // ========== Bit Manipulation ==========
        Piece { dst, hi, lo } => {
            // Concatenate: dst = (hi << lo.size*8) | lo
            let shift = lo.size * 8;
            format!("{},{},<<,{},|,{},=", vn(hi), shift, vn(lo), vn(dst))
        }

        Subpiece { dst, src, offset } => {
            // Extract: dst = (src >> offset*8) & mask
            let shift = offset * 8;
            if shift > 0 {
                format!("{},{},>>,{},=", vn(src), shift, vn(dst))
            } else {
                format!("{},{},=", vn(src), vn(dst))
            }
        }

        PopCount { dst, src } => format!("{},POPCOUNT,{},=", vn(src), vn(dst)),
        Lzcount { dst, src } => format!("{},CLZ,{},=", vn(src), vn(dst)),

        // ========== Control Flow ==========
        Branch { target } => format!("{},pc,=", vn(target)),

        CBranch { target, cond } => {
            // Conditional branch: if cond then goto target
            format!("{},?{{,{},pc,=,}}", vn(cond), vn(target))
        }

        BranchInd { target } => format!("{},pc,=", vn(target)),

        Call { target } => {
            // Call: push return address, jump to target
            format!("pc,8,rsp,-=,rsp,=[8],{},pc,=", vn(target))
        }

        CallInd { target } => {
            format!("pc,8,rsp,-=,rsp,=[8],{},pc,=", vn(target))
        }

        Return { target: _ } => {
            // Return: pop return address, jump
            format!("rsp,[8],pc,=,8,rsp,+=")
        }

        // ========== Floating Point ==========
        FloatAdd { dst, a, b } => format!("{},{},F+,{},=", vn(a), vn(b), vn(dst)),
        FloatSub { dst, a, b } => format!("{},{},F-,{},=", vn(a), vn(b), vn(dst)),
        FloatMult { dst, a, b } => format!("{},{},F*,{},=", vn(a), vn(b), vn(dst)),
        FloatDiv { dst, a, b } => format!("{},{},F/,{},=", vn(a), vn(b), vn(dst)),
        FloatNeg { dst, src } => format!("0,{},F-,{},=", vn(src), vn(dst)),
        FloatAbs { dst, src } => format!("{},FABS,{},=", vn(src), vn(dst)),
        FloatSqrt { dst, src } => format!("{},FSQRT,{},=", vn(src), vn(dst)),
        FloatCeil { dst, src } => format!("{},FCEIL,{},=", vn(src), vn(dst)),
        FloatFloor { dst, src } => format!("{},FFLOOR,{},=", vn(src), vn(dst)),
        FloatRound { dst, src } => format!("{},FROUND,{},=", vn(src), vn(dst)),
        FloatNaN { dst, src } => format!("{},FISNAN,{},=", vn(src), vn(dst)),
        FloatEqual { dst, a, b } => format!("{},{},F==,{},=", vn(a), vn(b), vn(dst)),
        FloatNotEqual { dst, a, b } => format!("{},{},F==,!,{},=", vn(a), vn(b), vn(dst)),
        FloatLess { dst, a, b } => format!("{},{},F<,{},=", vn(a), vn(b), vn(dst)),
        FloatLessEqual { dst, a, b } => format!("{},{},F<=,{},=", vn(a), vn(b), vn(dst)),
        Int2Float { dst, src } => format!("{},I2F,{},=", vn(src), vn(dst)),
        Float2Int { dst, src } => format!("{},F2I,{},=", vn(src), vn(dst)),
        FloatFloat { dst, src } => format!("{},F2F,{},=", vn(src), vn(dst)),
        Trunc { dst, src } => format!("{},FTRUNC,{},=", vn(src), vn(dst)),

        // ========== Special Operations ==========
        CallOther { output, userop, inputs } => {
            let args: Vec<String> = inputs.iter().map(|v| vn(v)).collect();
            let args_str = args.join(",");
            match output {
                Some(dst) => format!("{},CALLOTHER({}),{},=", args_str, userop, vn(dst)),
                None => format!("{},CALLOTHER({})", args_str, userop),
            }
        }

        Nop => String::new(),
        Unimplemented => "UNIMPL".to_string(),
        CpuId { dst } => format!("CPUID,{},=", vn(dst)),
        Breakpoint => "BREAK".to_string(),

        // Analysis operations (typically not in raw P-code from disassembly)
        Multiequal { dst, inputs } => {
            let args: Vec<String> = inputs.iter().map(|v| vn(v)).collect();
            format!("{},PHI,{},=", args.join(","), vn(dst))
        }

        Indirect { dst, src, .. } => format!("{},{},=", vn(src), vn(dst)),

        PtrAdd { dst, base, index, element_size } => {
            format!("{},{},{},*,+,{},=", vn(base), vn(index), element_size, vn(dst))
        }

        PtrSub { dst, base, index, element_size } => {
            format!("{},{},{},*,-,{},=", vn(base), vn(index), element_size, vn(dst))
        }

        SegmentOp { dst, segment, offset } => {
            // Segment:offset calculation (x86 real mode style)
            format!("{},4,<<,{},+,{},=", vn(segment), vn(offset), vn(dst))
        }

        New { dst, src } => format!("{},NEW,{},=", vn(src), vn(dst)),
        Cast { dst, src } => format!("{},{},=", vn(src), vn(dst)),

        Extract { dst, src, position } => {
            format!("{},{},>>,{},=", vn(src), vn(position), vn(dst))
        }

        Insert { dst, src, value, position } => {
            // Insert value into src at position
            format!("{},{},<<,{},|,{},=", vn(value), vn(position), vn(src), vn(dst))
        }
    }
}

#[cfg(feature = "sleigh-config")]
fn get_disassembler(arch: &str) -> Result<Disassembler, String> {
    match arch.to_lowercase().as_str() {
        #[cfg(feature = "x86")]
        "x86-64" | "x86_64" | "x64" | "amd64" => {
            Disassembler::from_sla(
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64"
            ).map_err(|e| e.to_string())
        }
        #[cfg(feature = "x86")]
        "x86" | "x86-32" | "i386" | "i686" => {
            Disassembler::from_sla(
                sleigh_config::processor_x86::SLA_X86,
                sleigh_config::processor_x86::PSPEC_X86,
                "x86"
            ).map_err(|e| e.to_string())
        }
        #[cfg(feature = "arm")]
        "arm" | "arm32" | "arm-le" => {
            Disassembler::from_sla(
                sleigh_config::processor_arm::SLA_ARM8_LE,
                sleigh_config::processor_arm::PSPEC_ARM8_LE,
                "ARM"
            ).map_err(|e| e.to_string())
        }
        _ => {
            let mut supported = vec![];
            #[cfg(feature = "x86")]
            supported.extend(["x86-64", "x86"]);
            #[cfg(feature = "arm")]
            supported.push("arm");

            if supported.is_empty() {
                Err("No architectures enabled. Build with --features x86 or --features arm".to_string())
            } else {
                Err(format!("Unknown architecture '{}'. Supported: {}", arch, supported.join(", ")))
            }
        }
    }
}
