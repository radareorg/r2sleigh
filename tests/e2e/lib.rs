//! E2E test harness for r2sleigh.
//!
//! Provides utilities to run radare2 commands and validate plugin output.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

fn r2_exec_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Get path to vuln_test binary (handles both workspace root and tests/e2e dir)
pub fn vuln_test_binary() -> &'static str {
    if Path::new("vuln_test").exists() {
        "vuln_test"
    } else if Path::new("tests/e2e/vuln_test").exists() {
        "tests/e2e/vuln_test"
    } else {
        "vuln_test" // Let it fail with a clear message
    }
}

/// Get path to test_func binary
pub fn test_func_binary() -> &'static str {
    if Path::new("test_func").exists() {
        "test_func"
    } else if Path::new("tests/e2e/test_func").exists() {
        "tests/e2e/test_func"
    } else {
        "test_func"
    }
}

/// Get path to stress_test binary
pub fn stress_test_binary() -> &'static str {
    if Path::new("stress_test").exists() {
        "stress_test"
    } else if Path::new("tests/e2e/stress_test").exists() {
        "tests/e2e/stress_test"
    } else {
        "stress_test"
    }
}

/// Get path to optimized stress_test binary
pub fn stress_test_opt_binary() -> &'static str {
    if Path::new("stress_test_opt").exists() {
        "stress_test_opt"
    } else if Path::new("tests/e2e/stress_test_opt").exists() {
        "tests/e2e/stress_test_opt"
    } else {
        "stress_test_opt"
    }
}

/// Legacy constants for compatibility
pub const VULN_TEST_BINARY: &str = "vuln_test";
pub const TEST_FUNC_BINARY: &str = "test_func";

/// Result of running an r2 command
#[derive(Debug)]
pub struct R2Result {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub crashed: bool,
    pub panicked: bool,
}

impl R2Result {
    /// Check if output contains expected pattern (regex-like grep match)
    pub fn contains(&self, pattern: &str) -> bool {
        self.stdout.contains(pattern) || self.stderr.contains(pattern)
    }

    /// Check if output contains any of the given patterns
    pub fn contains_any(&self, patterns: &[&str]) -> bool {
        patterns.iter().any(|p| self.contains(p))
    }

    /// Check if output contains all of the given patterns
    pub fn contains_all(&self, patterns: &[&str]) -> bool {
        patterns.iter().all(|p| self.contains(p))
    }

    /// Assert the command succeeded (no crash, no panic)
    pub fn assert_ok(&self) {
        assert!(!self.crashed, "Command crashed with exit code {:?}", self.exit_code);
        assert!(!self.panicked, "Command panicked: {}", self.stderr);
    }

    /// Try to parse stdout as JSON
    pub fn parse_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.stdout)
    }
}

/// Run radare2 with the given command on a binary
pub fn r2_cmd(binary: &str, cmd: &str) -> R2Result {
    r2_cmd_timeout(binary, cmd, Duration::from_secs(30))
}

/// Run radare2 with custom timeout
pub fn r2_cmd_timeout(binary: &str, cmd: &str, timeout: Duration) -> R2Result {
    let mut command = Command::new("timeout");
    command.args([
        &format!("{}s", timeout.as_secs()),
        "r2",
        "-q",
        "-e", "bin.relocs.apply=true",
        "-c", cmd,
        binary,
    ]);

    if let Ok(home) = std::env::var("HOME") {
        let plugin_dir = format!("{}/.local/share/radare2/plugins", home);
        command.env("R2_USER_PLUGINS", plugin_dir);
    }

    let _guard = r2_exec_lock().lock().ok();
    let output = command.output();

    parse_output(output)
}

/// Run radare2 without a timeout wrapper and with extra environment variables.
pub fn r2_cmd_with_env(binary: &str, cmd: &str, env: &[(&str, &str)]) -> R2Result {
    let mut command = Command::new("r2");
    command.args([
        "-q",
        "-e", "bin.relocs.apply=true",
        "-c", cmd,
        binary,
    ]);

    if let Ok(home) = std::env::var("HOME") {
        let plugin_dir = format!("{}/.local/share/radare2/plugins", home);
        command.env("R2_USER_PLUGINS", plugin_dir);
    }

    for (key, value) in env {
        command.env(key, value);
    }

    let _guard = r2_exec_lock().lock().ok();
    let output = command.output();
    parse_output(output)
}

/// Run radare2 with custom timeout and extra environment variables.
pub fn r2_cmd_timeout_with_env(
    binary: &str,
    cmd: &str,
    timeout: Duration,
    env: &[(&str, &str)],
) -> R2Result {
    let mut command = Command::new("timeout");
    command.args([
        &format!("{}s", timeout.as_secs()),
        "r2",
        "-q",
        "-e", "bin.relocs.apply=true",
        "-c", cmd,
        binary,
    ]);

    if let Ok(home) = std::env::var("HOME") {
        let plugin_dir = format!("{}/.local/share/radare2/plugins", home);
        command.env("R2_USER_PLUGINS", plugin_dir);
    }

    for (key, value) in env {
        command.env(key, value);
    }

    let _guard = r2_exec_lock().lock().ok();
    let output = command.output();
    parse_output(output)
}

/// Run r2 command seeking to a function first
pub fn r2_at_func(binary: &str, func: &str, cmd: &str) -> R2Result {
    let full_cmd = format!("aaa; s {}; {}", func, cmd);
    r2_cmd(binary, &full_cmd)
}

/// Run r2 command seeking to an address first  
pub fn r2_at_addr(binary: &str, addr: u64, cmd: &str) -> R2Result {
    let full_cmd = format!("aaa; s 0x{:x}; {}", addr, cmd);
    r2_cmd(binary, &full_cmd)
}

fn parse_output(output: Result<Output, std::io::Error>) -> R2Result {
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = out.status.code();
            
            // Detect real crashes: signal termination (SIGSEGV, SIGABRT, etc.) or
            // timeout-wrapper exit codes (128+signal).  Do NOT treat a plain non-zero
            // exit code as a crash — r2 legitimately returns non-zero sometimes.
            #[cfg(unix)]
            let crashed = out.status.signal().is_some()
                || matches!(exit_code, Some(134) | Some(139) | Some(136) | Some(137));
            #[cfg(not(unix))]
            let crashed = matches!(exit_code, Some(134) | Some(139) | Some(136) | Some(137));
            
            // Panic detection
            let panicked = stdout.contains("panicked") 
                || stderr.contains("panicked")
                || stdout.contains("core dumped")
                || stderr.contains("core dumped");

            R2Result { stdout, stderr, exit_code, crashed, panicked }
        }
        Err(e) => R2Result {
            stdout: String::new(),
            stderr: format!("Failed to execute r2: {}", e),
            exit_code: None,
            crashed: true,
            panicked: false,
        }
    }
}

/// Check that a test binary exists
pub fn require_binary(path: &str) {
    assert!(
        Path::new(path).exists(),
        "Test binary not found: {}. Compile it first.",
        path
    );
}

/// Check that the plugin is built
pub fn require_plugin() {
    let plugin_path = "target/release/libr2sleigh_plugin.so";
    assert!(
        Path::new(plugin_path).exists(),
        "Plugin not found at {}. Run `cargo build --release -p r2plugin` first.",
        plugin_path
    );
}
