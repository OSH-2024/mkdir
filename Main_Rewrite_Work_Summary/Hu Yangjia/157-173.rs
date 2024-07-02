

#[cfg(feature = CONFIG_BPF_KPROBE_OVERRIDE)]
unsafe fn bpf_override_return(regs: *mut pt_regs, rc: u64) -> i32 {
    regs_set_return_value(regs, rc);
    override_function_with_return(regs);
    0
}

let bpf_override_return_proto: bpf_func_proto = {
    .func		= bpf_override_return,
    .gpl_only	= true,
    .ret_type	= RET_INTEGER,
    .arg1_type	= ARG_PTR_TO_CTX,
    .arg2_type	= ARG_ANYTHING,
};
