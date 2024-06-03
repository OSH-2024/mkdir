// 1991-2015
// 定义 bpf_get_stack_proto_raw_tp 常量
const BPF_GET_STACK_PROTO_RAW_TP: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_get_stack_raw_tp),
    gpl_only: true,
    ret_type: RET_INTEGER,
    arg1_type: ARG_PTR_TO_CTX,
    arg2_type: ARG_PTR_TO_MEM | MEM_RDONLY,
    arg3_type: ARG_CONST_SIZE_OR_ZERO,
    arg4_type: ARG_ANYTHING,
};

// raw_tp_prog_func_proto 函数
pub fn raw_tp_prog_func_proto(func_id: bpf_func_id, prog: *const bpf_prog) -> *const bpf_func_proto {
    match func_id {
        BPF_FUNC_perf_event_output => &bpf_perf_event_output_proto_raw_tp,
        BPF_FUNC_get_stackid => &bpf_get_stackid_proto_raw_tp,
        BPF_FUNC_get_stack => &BPF_GET_STACK_PROTO_RAW_TP,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}