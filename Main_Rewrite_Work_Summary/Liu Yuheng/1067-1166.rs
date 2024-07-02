fn bpf_get_func_ip_kprobe(regs:Nonull<pt_regs>)-> i32 {
    unsafe{
        if cfg!(feature = "CONFIG_UPROBES") {
            let mut run_ctx : NonNull<bpf_trace_run_ctx>=container_of(current.bpf_ctx, bpf_trace_run_ctx, run_ctx);
            if (run_ctx.is_uprobe)!=0 {
                return *((current.utask.vaddr as NonNull<uprobe_dispatch_data>).as_ptr()).bp_addr;
            }
        } 
        else {
            let mut kp : NonNull<kprobe> = kprobe_running();
            if (!kp || !(kp.flags & KPROBE_FLAG_ON_FUNC_ENTRY)) {
		        return 0;
            }
            return get_entry_ip(kp.addr as uintptr_t);
        }  
    }
}
let  bpf_get_func_ip_proto_kprobe = bpf_func_proto{
	func		: bpf_get_func_ip_kprobe,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_func_ip_kprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_kprobe_multi_cookie(current.bpf_ctx);
}
let  bpf_get_attach_cookie_proto_kmulti = bpf_func_proto{
	func		: bpf_get_attach_cookie_kprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_func_ip_uprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_uprobe_multi_entry_ip(current.bpf_ctx);
}
let  bpf_get_func_ip_proto_uprobe_multi = bpf_func_proto{
	func		: bpf_get_func_ip_uprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_attach_cookie_uprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_uprobe_multi_cookie(current.bpf_ctx);
}
let  bpf_get_attach_cookie_proto_umulti = bpf_func_proto{
	func		: bpf_get_attach_cookie_uprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_attach_cookie_trace(ctx : NonNull<c_void>)-> i32{
    unsafe{
        let run_ctx : NonNull<bpf_trace_run_ctx> = container_of(current.bpf_ctx,  bpf_trace_run_ctx, run_ctx);
        return *(run_ctx.as_ptr()).cookie;
    }
}
let  bpf_get_attach_cookie_proto_trace = bpf_func_proto{
	func		: bpf_get_attach_cookie_trace,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_attach_cookie_pe(ctx : NonNull<bpf_perf_event_data_kern>){
    unsafe{
        return *(ctx.as_ptr()).event.bpf_cookie;
    }
}
let  bpf_get_attach_cookie_proto_pe = bpf_func_proto{
	func		: bpf_get_attach_cookie_pe,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
