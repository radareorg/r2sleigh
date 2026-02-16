use super::context::FoldArchConfig;

impl FoldArchConfig {
    pub(crate) fn is_return_register_name(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let base = lower.split('_').next().unwrap_or(lower.as_str());

        if base == self.ret_reg_name {
            return true;
        }

        if matches!(base, "xmm0" | "st0") {
            return true;
        }

        match self.ptr_size {
            64 => matches!(base, "rax" | "eax" | "ax" | "al"),
            _ => matches!(base, "eax" | "ax" | "al"),
        }
    }
}
