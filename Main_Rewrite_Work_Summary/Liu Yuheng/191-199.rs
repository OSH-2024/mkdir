let bpf_probe_read_user_proto = BpfFuncProto {
    func: bpf_probe_read_user, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RetInteger,
    arg1_type: ArgType::ArgPtrToUninitMem,
    arg2_type: ArgType::ArgConstSizeOrZero,
    arg3_type: ArgType::ArgAnything,
};