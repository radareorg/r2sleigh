pub struct EngineDecompileRequest {
    function_addr: u64,
}

pub struct EngineFunctionDecompileRequest {
    function_addr: u64,
}

pub struct EngineSession;

impl EngineSession {
    pub fn decompile(&self, request: EngineDecompileRequest) -> String {
        format!("0x{:x}", request.function_addr)
    }

    pub fn decompile_function(&self, request: EngineFunctionDecompileRequest) -> String {
        format!("0x{:x}", request.function_addr)
    }
}

fn main() {
    let session = EngineSession;
    let request = EngineFunctionDecompileRequest {
        function_addr: 0x401000,
    };
    let _ = session.decompile_function(request);
}
