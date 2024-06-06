//2090-2097
// tracing_prog_is_valid_access 函数的 Rust 实现
fn tracing_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 调用 bpf_tracing_btf_ctx_access 函数,传入偏移量、大小、访问类型、BPF 程序和访问信息
    // 返回访问是否有效
    bpf_tracing_btf_ctx_access(off, size, access_type, prog, info)
}