// 示例：创建一个BpfFuncProto实例
let bpf_get_func_ip_proto_tracing = BpfFuncProto {
    // 假设的外部函数，这里用一个示例函数来代替
    // 实际使用时，应该替换为正确的函数指针
    func: bpf_get_func_ip_tracing, // 假设的函数指针
    gpl_only: true,
    ret_type: RetType::Integer,
    arg1_type: ArgType::PtrToCtx,
};