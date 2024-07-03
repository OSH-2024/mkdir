//2146-2183
// pe_prog_is_valid_access 函数的 Rust 实现
fn pe_prog_is_valid_access(
    off: i32,
    size: usize,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 定义 u64 的大小
    let size_u64 = std::mem::size_of::<u64>() as i32;

    // 如果偏移量小于0或大于 bpf_perf_event_data 结构体的大小,返回 false
    if off < 0 || off >= std::mem::size_of::<bpf_perf_event_data>() as i32 {
        return false;
    }
    // 如果访问类型不是读,返回 false
    if access_type != bpf_access_type::BPF_READ {
        return false;
    }
    // 如果偏移量不是大小的整数倍
    if off % size as i32 != 0 {
        // 如果 unsigned long 不是 4 字节,返回 false
        if std::mem::size_of::<usize>() as i32 != 4 {
            return false;
        }
        // 如果大小不是 8 字节,返回 false
        if size != 8 {
            return false;
        }
        // 如果偏移量不是 4 的倍数,返回 false
        if off % 4 != 0 {
            return false;
        }
    }

    // 根据偏移量进行不同的处理
    match off {
        // bpf_perf_event_data 结构体的 sample_period 字段
        bpf_ctx_range!(bpf_perf_event_data, sample_period) => {
            // 记录字段大小为 u64
            bpf_ctx_record_field_size(info, size_u64);
            // 检查访问是否合法
            if !bpf_ctx_narrow_access_ok(off, size as i32, size_u64) {
                return false;
            }
        }
        // bpf_perf_event_data 结构体的 addr 字段
        bpf_ctx_range!(bpf_perf_event_data, addr) => {
            // 记录字段大小为 u64
            bpf_ctx_record_field_size(info, size_u64);
            // 检查访问是否合法
            if !bpf_ctx_narrow_access_ok(off, size as i32, size_u64) {
                return false;
            }
        }
        // 其他字段
        _ => {
            // 如果大小不是 long 的大小,返回 false
            if size != std::mem::size_of::<usize>() {
                return false;
            }
        }
    }

    // 访问合法
    true
}