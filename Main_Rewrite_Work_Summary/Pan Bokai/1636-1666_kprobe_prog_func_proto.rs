//1636-1666
// kprobe_prog_func_proto 函数的 Rust 实现
fn kprobe_prog_func_proto(func_id: bpf_func_id, prog: &bpf_prog) -> Option<&'static bpf_func_proto> {
    match func_id {
        bpf_func_id::BPF_FUNC_perf_event_output => Some(&BPF_PERF_EVENT_OUTPUT_PROTO),
        bpf_func_id::BPF_FUNC_get_stackid => Some(&BPF_GET_STACKID_PROTO),
        bpf_func_id::BPF_FUNC_get_stack => Some(&BPF_GET_STACK_PROTO),
        #[cfg(CONFIG_BPF_KPROBE_OVERRIDE)]
        bpf_func_id::BPF_FUNC_override_return => Some(&BPF_OVERRIDE_RETURN_PROTO),
        bpf_func_id::BPF_FUNC_get_func_ip => match prog.expected_attach_type {
            bpf_probe_attach_type::BPF_TRACE_KPROBE_MULTI => Some(&BPF_GET_FUNC_IP_PROTO_KPROBE_MULTI),
            bpf_probe_attach_type::BPF_TRACE_UPROBE_MULTI => Some(&BPF_GET_FUNC_IP_PROTO_UPROBE_MULTI),
            _ => Some(&BPF_GET_FUNC_IP_PROTO_KPROBE),
        },
        bpf_func_id::BPF_FUNC_get_attach_cookie => match prog.expected_attach_type {
            bpf_probe_attach_type::BPF_TRACE_KPROBE_MULTI => Some(&BPF_GET_ATTACH_COOKIE_PROTO_KMULTI),
            bpf_probe_attach_type::BPF_TRACE_UPROBE_MULTI => Some(&BPF_GET_ATTACH_COOKIE_PROTO_UMULTI),
            _ => Some(&BPF_GET_ATTACH_COOKIE_PROTO_TRACE),
        },
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}