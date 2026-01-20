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
use r2sleigh_lift::{format_op, op_to_esil, Disassembler};

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
fn annotate_register_names(value: &mut serde_json::Value, disasm: &Disassembler) {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            let is_varnode = map.contains_key("space") && map.contains_key("offset") && map.contains_key("size");
            if is_varnode {
                let space = map.get("space").and_then(Value::as_str);
                if let Some(space_str) = space {
                    if space_str.eq_ignore_ascii_case("register") {
                        let offset = map.get("offset").and_then(Value::as_u64);
                        let size = map.get("size").and_then(Value::as_u64);
                        if let (Some(offset), Some(size)) = (offset, size) {
                            let vn = r2il::Varnode {
                                space: r2il::SpaceId::Register,
                                offset,
                                size: size as u32,
                            };
                            if let Some(name) = disasm.register_name(&vn) {
                                map.insert("name".to_string(), Value::String(name));
                            }
                        }
                    }
                }
            }

            for value in map.values_mut() {
                annotate_register_names(value, disasm);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                annotate_register_names(item, disasm);
            }
        }
        _ => {}
    }
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
            let mut ops = Vec::new();
            for op in &block.ops {
                let mut value = serde_json::to_value(op)
                    .map_err(|e| format!("Failed to serialize op: {}", e))?;
                annotate_register_names(&mut value, &disasm);
                ops.push(value);
            }

            let json = serde_json::json!({
                "addr": format!("0x{:x}", block.addr),
                "size": size,
                "mnemonic": mnemonic,
                "ops": ops,
            });
            let output = serde_json::to_string_pretty(&json)
                .map_err(|e| format!("Failed to render JSON: {}", e))?;
            println!("{}", output);
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
                // sleigh-config 1.x does not ship an ARM8 pspec; use a Cortex pspec instead.
                sleigh_config::processor_arm::PSPEC_ARMCORTEX,
                "ARM"
            ).map_err(|e| e.to_string())
        }
        _ => {
            let mut supported: Vec<&str> = vec![];
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

#[cfg(all(test, feature = "sleigh-config", feature = "x86"))]
mod tests {
    use super::*;

    fn contains_named_register(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(map) => {
                let is_varnode =
                    map.contains_key("space") && map.contains_key("offset") && map.contains_key("size");
                if is_varnode {
                    let space = map.get("space").and_then(serde_json::Value::as_str);
                    if let Some(space_str) = space {
                        if space_str.eq_ignore_ascii_case("register") {
                            if let Some(name) = map.get("name").and_then(serde_json::Value::as_str) {
                                if !name.is_empty() {
                                    return true;
                                }
                            }
                        }
                    }
                }

                map.values().any(contains_named_register)
            }
            serde_json::Value::Array(items) => items.iter().any(contains_named_register),
            _ => false,
        }
    }

    #[test]
    fn disasm_json_includes_named_registers() {
        let disasm = get_disassembler("x86-64").expect("disassembler");
        let bytes = hex::decode("4889e500000000000000000000000000").expect("bytes");
        let block = disasm.lift(&bytes, 0x1000).expect("lift");

        let mut found = false;
        for op in &block.ops {
            let mut value = serde_json::to_value(op).expect("op json");
            annotate_register_names(&mut value, &disasm);
            if contains_named_register(&value) {
                found = true;
                break;
            }
        }

        assert!(found, "CLI JSON should include named register varnodes");
    }
}
