
static bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type,
    const struct bpf_prog *prog,
    struct bpf_insn_access_aux *info)
{
    if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
        return false;
    if (type != BPF_READ)
        return false;
    if (off % size != 0)
        return false;

    BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(__u64));
    return true;
}

// Compare this snippet from mkdir/Main_Rewrite_Work_Summary/Hu%20Yangjia/tp_prog_is_valid_access.rs:
pub fn tp_prog_is_valid_access(off: i32, size: i32, type_: bpf_access_type, 
    prog: *const bpf_prog, info: *mut bpf_insn_access_aux) -> bool {
    if off < std::mem::size_of::<*const std::ffi::c_void>() as i32 || off >= PERF_MAX_TRACE_SIZE as i32 
    {
        return false;
    }
    if type_ != BPF_READ {
        return false;
    }
    if off % size != 0 {
        return false;
    }

    BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % std::mem::size_of::<u64>() as i32);
    return true;
}
