pub fn artifact_guard_fallback_comment(func_name: &str, reason: &str) -> String {
    let func_name = crate::sanitize_comment_text(func_name);
    let reason = crate::sanitize_comment_text(reason);
    format!("/* r2sleigh refused {}: {} */", func_name, reason)
}
