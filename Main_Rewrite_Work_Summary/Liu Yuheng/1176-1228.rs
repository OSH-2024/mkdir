let  bpf_get_attach_cookie_proto_tracing = bpf_func_proto{
	func		: bpf_get_attach_cookie_tracing,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
};
fn bpf_get_branch_snapshot(buf:NonNull<c_void>,size:u32,flags:u64)->i32{
    unsafe{
        if(cfg!(feature != "CONFIG_X86")){
            return -ENOENT;
        }
        else {
            let br_entry_size : u32= size_of::<perf_branch_entry>();
            let mut entry_cnt : u32 = size/br_entry_size;
            entry_cnt = static_call(perf_snapshot_branch_stack)(buf.as_ptr(), entry_cnt);
            if unlikely(flags){
                return -EINVAL;
            }
            if !entry_cnt{
                return -ENOENT;
            }
            return entry_cnt * br_entry_size ;
        }
    }
}
let  bpf_get_branch_snapshot_proto = bpf_func_proto{
	func		: bpf_get_branch_snapshot,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_UNINIT_MEM,
	arg2_type	: ARG_CONST_SIZE_OR_ZERO,
};
fn get_func_arg(ctx:NonNull<c_void>,n:u32,value:NonNull<u64>)->i64{
    unsafe{
        // 将ctx从NonNull<c_void>转换为NonNull<u64>
        let ctx_u64 = ctx.cast::<u64>();
        // 使用offset方法访问前一个位置的指针，并解引用获取值
        let mut nr_args = *ctx_u64.as_ptr().offset(-1);
        // 根据需要使用nr_args
        if n as u64 >= nr_args{
            return -EINVAL;
        }
        *(value.as_ptr())= *ctx_u64.as_ptr().offset(n as isize);
        return 0;
    }
}
let  bpf_get_func_arg_proto = bpf_func_proto{
	func		: get_func_arg,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_ANYTHING,
	arg3_type	: ARG_PTR_TO_LONG,
};