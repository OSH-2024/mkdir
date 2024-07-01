fn bpf_send_signal(sig : u32)-> i32{
    return bpf_send_signal_common(sig, PIDTYPE_TGID);
}
let  bpf_send_signal_proto = bpf_func_proto{
	func		: bpf_send_signal,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_ANYTHING,
};
fn bpf_send_signal_thread(sig : u32)-> i32{
    return bpf_send_signal_common(sig, PIDTYPE_PID);
}
let  bpf_send_signal_thread_proto = bpf_func_proto{
	func		: bpf_send_signal_thread,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_ANYTHING,
};