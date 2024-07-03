// 1856-1886
// 定义 bpf_read_branch_records_proto 常量
const BPF_READ_BRANCH_RECORDS_PROTO: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_read_branch_records),
    gpl_only: true,
    ret_type: RET_INTEGER,
    arg1_type: ARG_PTR_TO_CTX,
    arg2_type: ARG_PTR_TO_MEM_OR_NULL,
    arg3_type: ARG_CONST_SIZE_OR_ZERO,
    arg4_type: ARG_ANYTHING,
};

// pe_prog_func_proto 函数
pub fn pe_prog_func_proto(func_id: bpf_func_id, prog: *const bpf_prog) -> *const bpf_func_proto {
    match func_id {
        BPF_FUNC_perf_event_output => &bpf_perf_event_output_proto_tp,
        BPF_FUNC_get_stackid => &bpf_get_stackid_proto_pe,
        BPF_FUNC_get_stack => &bpf_get_stack_proto_pe,
        BPF_FUNC_perf_prog_read_value => &bpf_perf_prog_read_value_proto,
        BPF_FUNC_read_branch_records => &BPF_READ_BRANCH_RECORDS_PROTO,
        BPF_FUNC_get_attach_cookie => &bpf_get_attach_cookie_proto_pe,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}