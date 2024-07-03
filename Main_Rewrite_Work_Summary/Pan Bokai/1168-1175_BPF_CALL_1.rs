//1168-1175
// BPF_CALL_1 宏的 Rust 实现
macro_rules! BPF_CALL_1 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(ctx: *mut c_void) -> u64 {
            // 获取当前线程的 bpf_ctx
            let bpf_ctx = current().bpf_ctx;
            
            // 使用 container_of 宏从 bpf_ctx 中获取 BpfTraceRunCtx 结构体
            let run_ctx = container_of(bpf_ctx, BpfTraceRunCtx, run_ctx);
            
            // 返回 BpfTraceRunCtx 结构体中的 bpf_cookie 字段
            run_ctx.bpf_cookie
        }
    };
}