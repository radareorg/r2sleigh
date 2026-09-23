use std::fs;
use std::path::Path;

#[test]
fn engine_route_policy_never_uses_renderer_route_type() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = fs::read_dir(&src_dir)
        .expect("r2engine src directory should exist")
        .map(|entry| entry.expect("source file entry should be readable").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect::<Vec<_>>();
    files.sort();

    let mut violations = Vec::new();

    for file in files {
        let rel = file
            .strip_prefix(&src_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).expect("source file should be UTF-8");
        for (line_idx, line) in text.lines().enumerate() {
            if !line.contains("r2dec::SemanticRoutePlan") && !line.contains("to_decompiler_route") {
                continue;
            }
            violations.push(format!("{}:{} {}", rel, line_idx + 1, line.trim()));
        }
    }

    assert!(
        violations.is_empty(),
        "r2engine route policy must not depend on renderer route types or conversion helpers.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn engine_public_api_never_exposes_renderer_config_or_context_types() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = fs::read_dir(&src_dir)
        .expect("r2engine src directory should exist")
        .map(|entry| entry.expect("source file entry should be readable").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect::<Vec<_>>();
    files.sort();

    let mut violations = Vec::new();

    for file in files {
        let rel = file
            .strip_prefix(&src_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).expect("source file should be UTF-8");
        for (line_idx, line) in text.lines().enumerate() {
            let renderer_config = line.contains("r2dec::DecompilerConfig");
            let renderer_context = line.contains("r2dec::DecompilerContext");
            let renderer_input = line.contains("r2dec::DecompilerInput");
            let route_context_adapter = line.contains("decompiler_context_with_route_decision");
            if !(renderer_config || renderer_context || renderer_input || route_context_adapter) {
                continue;
            }

            let allowed_config_adapter = rel == "lib.rs"
                && renderer_config
                && (line.contains("to_decompiler_config")
                    || line.contains("r2dec::DecompilerConfig::for_arch_name"));
            let allowed_private_render_bridge = rel == "lib.rs"
                && (renderer_context || renderer_input || route_context_adapter)
                && !line.contains("pub ");
            let allowed_crate_private_route_adapter = rel == "route.rs"
                && (renderer_context || route_context_adapter)
                && (line.contains("pub(crate)")
                    || line.contains("context:")
                    || line.contains(") -> r2dec::DecompilerContext"));
            if !(allowed_config_adapter
                || allowed_private_render_bridge
                || allowed_crate_private_route_adapter)
            {
                violations.push(format!("{}:{} {}", rel, line_idx + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "r2engine public contracts must use engine-owned render types and convert to r2dec only at the private renderer adapter boundary.\n\
         Violations:\n{}",
        violations.join("\n")
    );
}

/// The engine never opens anything. Whoever opened the binary hands it the
/// bytes and what the container states through `program::Source`, which is
/// what lets every engine test run over a program built from byte literals.
#[test]
fn the_engine_knows_no_file() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the engine has a manifest");
    let dependencies = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("the manifest declares dependencies");
    assert!(
        !dependencies.lines().any(|line| line.starts_with("r2image")),
        "the engine depends on the container parser"
    );
    let violations: Vec<String> = sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
        .into_iter()
        .flat_map(|path| {
            let text = fs::read_to_string(&path).expect("the source is UTF-8");
            text.lines()
                .enumerate()
                .filter(|(_, line)| {
                    ["std::fs", "File::open", "Image::open", "r2image::"]
                        .iter()
                        .any(|needle| line.contains(needle))
                })
                .map(|(index, line)| format!("{}:{} {}", path.display(), index + 1, line.trim()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        violations.is_empty(),
        "the engine reaches for a file:\n{}",
        violations.join("\n")
    );
}

/// Every Rust source under a directory, however deep.
fn sources(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for path in fs::read_dir(&at)
            .expect("the source directory exists")
            .map(|entry| entry.expect("the entry is readable").path())
        {
            match path.is_dir() {
                true => pending.push(path),
                false if path.extension().is_some_and(|ext| ext == "rs") => found.push(path),
                false => {}
            }
        }
    }
    found
}

#[test]
fn no_crate_hides_dead_code() {
    // Nineteen of these hid seven unused types, a context no pass built, a
    // stack table written and never read, and helpers only tests reached.
    // Code a test alone needs is `#[cfg(test)]`; code nothing needs is gone.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let files = fs::read_dir(&crates)
        .expect("the crates directory exists")
        .map(|entry| entry.expect("the entry is readable").path().join("src"))
        .filter(|src| src.is_dir())
        .flat_map(|src| sources(&src));
    let mut hiding = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("the source is UTF-8");
        let hidden = text.lines().enumerate().filter(|(_, line)| {
            ["allow(dead_code", "expect(dead_code", "allow(unused)"]
                .iter()
                .any(|hidden| line.contains(hidden))
        });
        hiding.extend(hidden.map(|(index, _)| format!("{}:{}", file.display(), index + 1)));
    }
    hiding.sort();
    assert!(
        hiding.is_empty(),
        "dead code is hidden rather than deleted:\n{}",
        hiding.join("\n")
    );
}
