use core::ffi::c_void;

#[cfg(feature = CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE)]
BPF_CALL_3(bpf_probe_read_compat, *mut c_void, dst, u32, size, *const c_void, unsafe_ptr) 
{
    if unsafe_ptr as usize < TASK_SIZE {
        bpf_probe_read_user_common(dst, size, unsafe_ptr as *const _)
    } 
    else 
    {
        bpf_probe_read_kernel_common(dst, size, unsafe_ptr)
    }
}


let bpf_probe_read_compat_proto:bpf_func_proto={
    .func=bpf_probe_read_compat,
    .gpl_only=true,
    .ret_type=RET_INTEGER,
    .arg1_type=ARG_PTR_TO_UNINIT_MEM,
    .arg2_type=ARG_CONST_SIZE_OR_ZERO,
    .arg3_type=ARG_ANYTHING,
};

BPF_CALL_3(bpf_probe_read_compat_str, *mut c_void, dst, u32, size, *mut c_void, unsafe_ptr)
{
    if (unsafe_ptr as usize< TASK_SIZE) 
    {
        return bpf_probe_read_user_str_common(dst, size, unsafe_ptr as *mut c_void);
    }
    return bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr);
}
let bpf_probe_read_compat_str_proto: bpf_func_proto=
{
    .func=bpf_probe_read_compat_str,
    .gpl_only=true,
    .ret_type=RET_INTEGER,
    .arg1_type=ARG_PTR_TO_UNINIT_MEM,
    .arg2_type=ARG_CONST_SIZE_OR_ZERO,
    .arg3_type=ARG_ANYTHING,
};