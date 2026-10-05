use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use heck::ToSnakeCase;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    let mut config_vars_file = File::create(Path::new(&out_dir).join("config_vars.rs"))?;

    let processors_root = "ghidra/Ghidra/Processors";
    let mut sla_data = Vec::new();
    let mut pspec_data = Vec::new();
    let mut cspec_data = Vec::new();

    for processor_dir in std::fs::read_dir(Path::new(processors_root))?.filter_map(Result::ok) {
        let processor_name = processor_dir.file_name().to_str().unwrap().to_owned();
        let feature_env_name = processor_name.to_uppercase().replace("-", "_");

        // Check if Ghidra/Processors/{FeatureName} is enabled
        if std::env::var(format!("CARGO_FEATURE_{feature_env_name}")).is_ok() {
            // Compile all slaspec files found under Ghidra/Processors/{FeatureName}/data/languages
            // pub mod NAME {
            let mod_name = format!(
                "processor_{name}",
                name = processor_name.replace("-", "_").to_snake_case()
            );

            writeln!(
                &mut config_vars_file,
                r#"/// Configurations for the processor `{processor_name}`"#
            )?;
            writeln!(&mut config_vars_file, r#"pub mod {mod_name} {{"#)?;

            for lang_entry in std::fs::read_dir(processor_dir.path().join("data/languages"))?
                .filter_map(Result::ok)
            {
                let file_stem = lang_entry.path().file_stem().unwrap().display().to_string();
                let var_name = file_stem.replace("-", "_").replace(".", "_").to_uppercase();

                match lang_entry.path().extension() {
                    Some(ext) if ext == "slaspec" => {
                        // File extension is slaspec
                        let output_path = Path::new(&out_dir).join(format!("{file_stem}.sla"));
                        let var_name = format!("SLA_{var_name}");

                        let mut compiler = sleigh_compiler::SleighCompiler::default();
                        compiler.compile(lang_entry.path(), &output_path)?;
                        writeln!(
                            &mut config_vars_file,
                            r##"pub const {var_name}: &'static [u8] = include_bytes!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        sla_data.push(format!("{mod_name}::{var_name}"));
                    }
                    Some(ext) if ext == "pspec" => {
                        // File extension is pspec
                        let var_name = format!("PSPEC_{var_name}");
                        let output_path = Path::new(&out_dir).join(lang_entry.file_name());
                        std::fs::copy(lang_entry.path(), &output_path)?;

                        writeln!(
                            &mut config_vars_file,
                            r##"pub const {var_name}: &'static str = include_str!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        pspec_data.push(format!("{mod_name}::{var_name}"));
                    }
                    Some(ext) if ext == "cspec" => {
                        // File extension is cspec. It names the stack pointer
                        // and the prototype models, which nothing else carries.
                        let var_name = format!("CSPEC_{var_name}");
                        let output_path = Path::new(&out_dir).join(lang_entry.file_name());
                        std::fs::copy(lang_entry.path(), &output_path)?;

                        writeln!(
                            &mut config_vars_file,
                            r##"pub const {var_name}: &'static str = include_str!(r#"{path}"#);"##,
                            path = output_path.display()
                        )?;

                        cspec_data.push(format!("{mod_name}::{var_name}"));
                    }

                    // No match, nothing to do
                    _ => (),
                } // End match
            } // End language directory for loop
            writeln!(&mut config_vars_file, r#"}}"#)?;
        } // End feature check
    } // End processor directory for loop

    writeln!(
        &mut config_vars_file,
        r##"pub const SLA_DATA: [(&'static str, &'static [u8]); {len}] = ["##,
        len = sla_data.len()
    )?;
    for entry in &sla_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    writeln!(
        &mut config_vars_file,
        r##"pub const PSPEC_DATA: [(&'static str, &'static str); {len}] = ["##,
        len = pspec_data.len()
    )?;
    for entry in &pspec_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    writeln!(
        &mut config_vars_file,
        r##"pub const CSPEC_DATA: [(&'static str, &'static str); {len}] = ["##,
        len = cspec_data.len()
    )?;
    for entry in &cspec_data {
        writeln!(&mut config_vars_file, r##"(r#"{entry}"#, &{entry}),"##)?;
    }
    writeln!(&mut config_vars_file, r##"];"##)?;

    Ok(())
}
