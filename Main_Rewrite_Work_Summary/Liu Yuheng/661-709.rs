use std::ffi::c_void;
use std::ptr::NonNull;
fn bpf_perf_event_output(regs: NonNull<pt_regs>,map: NonNull<bpf_map>,flags:u64,data:NonNull<void>,size:u64)-> Result<(), i32>{
    let raw = perf_raw_record {
        frag: perf_frag_record {
            size,
            data: data.as_ptr(),
        },
    };

    // 禁用抢占和处理嵌套级别
    // Rust没有直接的抢占禁用机制，这里省略
    let nest_level = BPF_TRACE_NEST_LEVEL.with(|level| {
        *level.borrow_mut() += 1;
        *level.borrow()
    });

    let err = BPF_TRACE_SDS.with(|sds| {
        let mut sds = sds.borrow_mut();
        let sds = sds.get_or_insert_with(|| bpf_trace_sample_data { sds: Vec::new() });

        if nest_level as usize > sds.sds.len() {
            return Err(EBUSY);
        }

        if flags & !BPF_F_INDEX_MASK != 0 {
            return Err(EINVAL);
        }

        // 假设的初始化和保存数据函数
        let sd = perf_sample_data_init(0, 0);
        perf_sample_save_raw_data(&sd, &raw);

        // 假设的输出函数
        __bpf_perf_event_output(regs, map, flags, &sd)
    });

    // 减少嵌套级别
    BPF_TRACE_NEST_LEVEL.with(|level| *level.borrow_mut() -= 1);

    err
}

let bpf_perf_event_output_proto = BpfFuncProto {
    func: bpf_perf_event_output, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_CTX,
    arg2_type: ArgType::ARG_CONST_MAP_PTR,
    arg3_type: ArgType:ARG_ANYTHING,
    arg4_type: ArgType:ARG_PTR_TO_MEM | MEM_RDONLY,
    arg5_type: ArgType:ARG_CONST_SIZE_OR_ZERO,
};