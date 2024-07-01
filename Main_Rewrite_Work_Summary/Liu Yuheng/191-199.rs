let bpf_probe_read_user_proto = BpfFuncProto {
    func: bpf_probe_read_user, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,
};