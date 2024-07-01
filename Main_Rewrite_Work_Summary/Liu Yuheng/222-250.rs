use std::ffi::c_void;
use std::ptr::NonNull;
fn bpf_probe_read_user_str(dst: NonNull<c_void>,size: u32,unsafe_ptr:NonNull<c_void>) -> i32{
    let ret = bpf_probe_read_user_str_common(dst, size, unsafe_ptr);
    ret
}
let bpf_probe_read_user_str_proto = BpfFuncProto {
    func: bpf_probe_read_user_str, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,
};
fn bpf_probe_read_kernel(dst: NonNull<c_void>,size: u32,unsafe_ptr:NonNull<c_void>) -> i32{
    let ret = bpf_probe_read_kernel_common(dst, size, unsafe_ptr);
    ret
}
let bpf_probe_read_kernel_proto = BpfFuncProto {
    func: bpf_probe_read_kernel, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,
};