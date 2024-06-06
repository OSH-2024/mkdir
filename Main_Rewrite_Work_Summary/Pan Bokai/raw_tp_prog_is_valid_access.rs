//2082-2089
// raw_tp_prog_is_valid_access 函数的 Rust 实现
fn raw_tp_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 调用 bpf_tracing_ctx_access 函数,传入偏移量、大小和访问类型
    // 返回访问是否有效
    bpf_tracing_ctx_access(off, size, access_type)
}