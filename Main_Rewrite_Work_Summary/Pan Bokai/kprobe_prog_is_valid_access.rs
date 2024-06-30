//1667-1687
// kprobe_prog_is_valid_access 函数的 Rust 实现
// bpf+kprobe 程序可以访问 'struct pt_regs' 的字段
fn kprobe_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 检查偏移量是否在 'struct pt_regs' 的范围内
    if off < 0 || off >= std::mem::size_of::<pt_regs>() as i32 {
        return false;
    }
    // 检查访问类型是否为读
    if access_type != bpf_access_type::BPF_READ {
        return false;
    }
    // 检查偏移量是否与访问大小对齐
    if off % size != 0 {
        return false;
    }
    // 断言: 对于 32 位系统,确保最后 8 字节访问 (BPF_DW) 到最后 4 字节成员是不允许的
    if off as usize + size as usize > std::mem::size_of::<pt_regs>() {
        return false;
    }

    true
}