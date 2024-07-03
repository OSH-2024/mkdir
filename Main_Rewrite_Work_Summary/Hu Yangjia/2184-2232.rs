

fn pe_prog_convert_ctx_access(type: bpf_access_type, si: *mut bpf_insn, insn_buf: *mut bpf_insn, prog: *mut bpf_prog, target_size: *mut u32) -> u32 
{
    let insn: *mut bpf_insn = insn_buf;
    match si.off
    {
        offsetof(bpf_perf_event_data, sample_period) => 
        {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, data), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, data));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_DW, si.dst_reg, si.dst_reg, bpf_target_off(perf_sample_data, period, 8, target_size));
            insn += 1;
        },
        offsetof(bpf_perf_event_data, addr) => {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, data), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, data));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_DW, si.dst_reg, si.dst_reg, bpf_target_off(perf_sample_data, addr, 8, target_size));
            insn += 1;
        },
        _ => {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, regs), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, regs));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_SIZEOF(long), si.dst_reg, si.dst_reg, si.off);
            insn += 1;
        }
    }
    return insn - insn_buf;
}

let perf_event_verifier_ops: bpf_verifier_ops = bpf_verifier_ops 
{
    get_func_proto = pe_prog_func_proto,
    is_valid_access = pe_prog_is_valid_access,
    convert_ctx_access = pe_prog_convert_ctx_access
}


// 定义 perf_event 程序操作
const PERF_EVENT_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
    // 这里可以添加 perf_event 程序操作的字段和函数指针
    // 例如:
    // run: None,
    // verify: None,
    // fixup_attach_type: None,
    // init: None,
    // check_attach_type: None,
    // is_tracing_prog: None,
};

// 定义 bpf_event_mutex 互斥锁
lazy_static! {
    static ref BPF_EVENT_MUTEX: Mutex<()> = Mutex::new(());
}

// 定义 BPF 跟踪程序的最大数量
const BPF_TRACE_MAX_PROGS: usize = 64;
