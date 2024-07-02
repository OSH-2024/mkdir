
#[cfg(feature = CONFIG_NET)]
fn tracing_prog_func_proto(func_id: bpf_func_id, prog: *mut bpf_prog )-> *mut bpf_func_proto
{
    let fn: *mut bpf_func_proto;
    match (func_id)
    {
        BPF_FUNC_skb_output => return &bpf_skb_output_proto,
        BPF_FUNC_xdp_output => return &bpf_xdp_output_proto,
        BPF_FUNC_skc_to_tcp6_sock => return &bpf_skc_to_tcp6_sock_proto,
        BPF_FUNC_skc_to_tcp_sock => return &bpf_skc_to_tcp_sock_proto,
        BPF_FUNC_skc_to_tcp_timewait_sock => return &bpf_skc_to_tcp_timewait_sock_proto,
        BPF_FUNC_skc_to_tcp_request_sock => return &bpf_skc_to_tcp_request_sock_proto,
        BPF_FUNC_skc_to_udp6_sock => return &bpf_skc_to_udp6_sock_proto,
        BPF_FUNC_skc_to_unix_sock => return &bpf_skc_to_unix_sock_proto,
        BPF_FUNC_skc_to_mptcp_sock => return &bpf_skc_to_mptcp_sock_proto,
        BPF_FUNC_sk_storage_get => return &bpf_sk_storage_get_tracing_proto,
        BPF_FUNC_sk_storage_delete => return &bpf_sk_storage_delete_tracing_proto,
        BPF_FUNC_sock_from_file => return &bpf_sock_from_file_proto,
        BPF_FUNC_get_socket_cookie => return &bpf_get_socket_ptr_cookie_proto,
        BPF_FUNC_xdp_get_buff_len => return &bpf_xdp_get_buff_len_trace_proto,
        BPF_FUNC_seq_printf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_proto : NULL,
        BPF_FUNC_seq_write => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_write_proto : NULL,
        BPF_FUNC_seq_printf_btf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_btf_proto : NULL,
        BPF_FUNC_d_path => return &bpf_d_path_proto,
        BPF_FUNC_get_func_arg => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_proto : NULL,
        BPF_FUNC_get_func_ret => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_ret_proto : NULL,
        BPF_FUNC_get_func_arg_cnt => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_cnt_proto : NULL,
        BPF_FUNC_get_attach_cookie => return bpf_prog_has_trampoline(prog) ? &bpf_get_attach_cookie_proto_tracing : NULL,
        _ => {
            fn = raw_tp_prog_func_proto(func_id, prog);
            if !fn && prog->expected_attach_type == BPF_TRACE_ITER
            {
                fn = bpf_iter_get_func_proto(func_id, prog);
            }
            return fn;
        }

    }
}

#[cfg(not(feature = CONFIG_NET))]
fn tracing_prog_func_proto(func_id: bpf_func_id, prog: *mut bpf_prog )-> *mut bpf_func_proto
{
    let fn: *mut bpf_func_proto;
    match (func_id)
    {
        BPF_FUNC_seq_printf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_proto : NULL,
        BPF_FUNC_seq_write => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_write_proto : NULL,
        BPF_FUNC_seq_printf_btf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_btf_proto : NULL,
        BPF_FUNC_d_path => return &bpf_d_path_proto,
        BPF_FUNC_get_func_arg => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_proto : NULL,
        BPF_FUNC_get_func_ret => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_ret_proto : NULL,
        BPF_FUNC_get_func_arg_cnt => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_cnt_proto : NULL,
        BPF_FUNC_get_attach_cookie => return bpf_prog_has_trampoline(prog) ? &bpf_get_attach_cookie_proto_tracing : NULL,
        _ => {
            fn = raw_tp_prog_func_proto(func_id, prog);
            if !fn && prog->expected_attach_type == BPF_TRACE_ITER
            {
                fn = bpf_iter_get_func_proto(func_id, prog);
            }
            return fn;
        }

    }
}