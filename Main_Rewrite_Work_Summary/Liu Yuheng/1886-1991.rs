struct  bpf_raw_tp_regs{
    regs: [pt_regs; 3],
}
unsafe{
    bindings::DEFINE_PER_CPU(struct bpf_raw_tp_regs, bpf_raw_tp_regs);
    bindings::DEFINE_PER_CPU(int, bpf_raw_tp_nest_level);
}
fn get_bpf_raw_tp_regs()->*mut bpf_raw_tp_regs{
    unsafe{
        let mut tp_regs:NonNull<bpf_raw_tp_regs> = bindings::this_cpu_ptr(&bpf_raw_tp_regs);
        let mut nest_level:i32 = bindings::this_cpu_read(&bpf_raw_tp_nest_level);
        if bindings::WARN_ON_ONCE(nest_level > bindings::ARRAY_SIZE(*(tp_regs.as_ptr()).regs)){
            bindings::this_cpu_dec(bpf_raw_tp_nest_level);
            return ERR_PTR(-EBUSY);
        }
        let regs_ptr: *mut PtRegs = (*tp_regs.as_ptr()).regs.as_mut_ptr().add(nest_level as usize - 1);
        Ok(regs_ptr)
    }
}
fn put_bpf_raw_tp_regs{
    unsafe{
        bindings::this_cpu_dec(bpf_raw_tp_nest_level);
    }
}
fn bpf_perf_event_output_raw_tp(args:NonNull<bpf_raw_tracepoint_args>,map:NonNull<bpf_map>,flags:u64,data:NonNull<c_void>,size:u64)->i32{
    unsafe{
        let mut regs : *mut pt_regs = get_bpf_raw_tp_regs();
        if IS_ERR(regs){
            return PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::____bpf_perf_event_output(regs, map, flags, data, size);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}
let  bpf_perf_event_output_proto_raw_tp = bpf_func_proto{
	func		: bpf_perf_event_output_raw_tp,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_CONST_MAP_PTR,
	arg3_type	: ARG_ANYTHING,
	arg4_type	: ARG_PTR_TO_MEM | MEM_RDONLY,
	arg5_type	: ARG_CONST_SIZE_OR_ZERO,
};
extern "C" {
    static bpf_skb_output_proto: bpf_func_proto;
    static bpf_xdp_output_proto: bpf_func_proto;
    static bpf_xdp_get_buff_len_trace_proto;
}
fn bpf_get_stackid_raw_tp(args:NonNull<bpf_raw_tracepoint_args>,map:NonNull<bpf_map>,flags:u64){
    unsafe{
        let mut regs : *mut pt_regs = get_bpf_raw_tp_regs();
        if IS_ERR(regs){
            return PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::bpf_get_stackid( regs as u64,  map as u64,flags, 0, 0);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}
let  bpf_get_stackid_proto_raw_tp = bpf_func_proto{
	func		: bpf_get_stackid_raw_tp,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_CONST_MAP_PTR,
	arg3_type	: ARG_ANYTHING,
};
fn bpf_get_stack_raw_tp(args : NonNull<bpf_raw_tracepoint_args>,buf:NonNull<c_void>,size:u32,flags:u64){
    unsafe{
        let mut regs : *mut pt_regs = bindings::get_bpf_raw_tp_regs();
        if bindings::IS_ERR(regs){
            return bindings::PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::bpf_get_stack( regs as u64,  buf as u64, size, flags,0);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}