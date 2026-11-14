#![allow(dead_code)]

struct CFG;

struct SSAFunction {
    entry: u64,
    cfg: CFG,
}

impl SSAFunction {
    fn cfg(&self) -> &CFG {
        &self.cfg
    }

    fn call_passes(&self) -> bool {
        false
    }
}

struct SourceMachineContext;

impl SourceMachineContext {
    fn raw_call_site_at(&self, _instruction: u64) -> Option<u64> {
        None
    }

    fn call_reads(&self, _instruction: u64) -> Option<u64> {
        None
    }
}

#[derive(Clone, Copy)]
struct BuildFacts<'a> {
    function: &'a SSAFunction,
    context: &'a SourceMachineContext,
}

impl<'a> BuildFacts<'a> {
    fn entry(&self) -> u64 {
        self.function.entry
    }

    fn cfg(&self) -> &'a CFG {
        self.function.cfg()
    }

    fn raw_call_site_at(&self, instruction: u64) -> Option<u64> {
        self.context.raw_call_site_at(instruction)
    }

    fn call_passes(&self) -> bool {
        self.function.call_passes()
    }

    fn call_reads(&self, instruction: u64) -> Option<u64> {
        self.context.call_reads(instruction)
    }

    fn function(&self) -> &'a SSAFunction {
        self.function
    }
}

fn main() {
    let function = SSAFunction {
        entry: 0,
        cfg: CFG,
    };
    let build = BuildFacts {
        function: &function,
        context: &SourceMachineContext,
    };
    let _ = (build.entry(), build.cfg(), build.raw_call_site_at(0));
    let _ = (build.call_passes(), build.call_reads(0), build.function().entry);
}
