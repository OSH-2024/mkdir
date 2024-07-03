//2125-2137
// raw_tp_writable_prog_is_valid_access 函数的 Rust 实现
fn raw_tp_writable_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    if off == 0 {
        // 如果偏移量为0
        if size != std::mem::size_of::<u64>() as i32 || access_type != bpf_access_type::BPF_READ {
            // 如果大小不等于 u64 的大小或访问类型不是读,返回 false
            return false;
        }
        // 将 info 的 reg_type 字段设置为 PTR_TO_TP_BUFFER
        info.reg_type = bpf_reg_type::PTR_TO_TP_BUFFER;
    }
    // 调用 raw_tp_prog_is_valid_access 函数,传入偏移量、大小、访问类型、BPF 程序和访问信息
    // 返回访问是否有效
    raw_tp_prog_is_valid_access(off, size, access_type, prog, info)
}