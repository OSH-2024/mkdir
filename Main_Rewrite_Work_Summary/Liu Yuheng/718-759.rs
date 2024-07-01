fn bpf_event_output(map:NonNull<bpf_map>, flags:u64 , meta:NonNull<c_void>, meta_size:u64 ,ctx:NonNull<c_void>, ctx_size:u64 , ctx_copy:bpf_ctx_copy_t )->u64{
    let frag= perf_raw_frag{
        copy: ctx_copy,
        size: ctx_size,
        data: ctx.as_ptr(),
    };
    struct PerfRawRecord {
        frag: PerfRawFrag,
    }
    
    // 假设frag已经被正确地定义和初始化
    let raw = PerfRawRecord {
        frag: PerfRawFrag {
            next: if ctx_size > 0 { Some(&frag as *const _) } else { None },
            size: meta_size,
            data: meta as *const u32, // 假设meta可以被转换为*const u8
        },
    };
    let mut sd = NonNull<perf_sample_data>;
    let mut regs = NonNull<pt_regs>;
    preempt_disable();
    let mut nest_level : i32= this_cpu_inc_return(bpf_event_output_nest_level);
    if WARN_ON_ONCE(nest_level as usize > ARRAY_SIZE ){
        // 错误处理，使用Result返回错误
        this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
        preempt_enable();
        return Err(-EBUSY);
    }

    let sd = this_cpu_ptr(&BPF_MISC_SDS.sds[nest_level - 1]);
    let regs = this_cpu_ptr(&BPF_PT_REGS.regs[nest_level - 1]);

    perf_fetch_caller_regs(regs);
    perf_sample_data_init(sd, 0, 0);
    perf_sample_save_raw_data(sd, &raw);

    let ret = __bpf_perf_event_output(regs, map.as_ptr(), flags, sd)?;

    // 正确的退出点
    this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
    preempt_enable();
    Ok(ret)
}