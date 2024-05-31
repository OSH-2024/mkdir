// 1828-1855
// BPF_CALL_4 宏的 Rust 实现
macro_rules! BPF_CALL_4 {
    ($func:ident, $($arg:ty),+) => {
        #[no_mangle]
        pub unsafe extern "C" fn $func(ctx: *mut bpf_perf_event_data_kern, buf: *mut u8, size: u32, flags: u64) -> i32 {
            // 定义常量 br_entry_size,表示 perf_branch_entry 结构体的大小
            const BR_ENTRY_SIZE: u32 = std::mem::size_of::<perf_branch_entry>() as u32;

            // 检查 flags 参数是否合法
            if unlikely((flags & !BPF_F_GET_BRANCH_RECORDS_SIZE) != 0) {
                return -EINVAL;
            }

            // 获取 ctx->data->br_stack 指针
            let br_stack = (*ctx).data.as_ref().and_then(|data| data.br_stack.as_ref());

            // 如果 ctx->data->sample_flags 不包含 PERF_SAMPLE_BRANCH_STACK 标志,则返回 -ENOENT
            if unlikely(!((*ctx).data.as_ref().map_or(false, |data| data.sample_flags & PERF_SAMPLE_BRANCH_STACK != 0))) {
                return -ENOENT;
            }

            // 如果 br_stack 为 null,则返回 -ENOENT
            if unlikely(br_stack.is_none()) {
                return -ENOENT;
            }

            // 如果 flags 包含 BPF_F_GET_BRANCH_RECORDS_SIZE 标志,则返回 br_stack 中条目的总大小
            if flags & BPF_F_GET_BRANCH_RECORDS_SIZE != 0 {
                return (br_stack.unwrap().nr * BR_ENTRY_SIZE) as i32;
            }

            // 检查 buf 和 size 参数是否合法
            if buf.is_null() || (size % BR_ENTRY_SIZE != 0) {
                return -EINVAL;
            }

            // 计算需要复制的数据大小
            let to_copy = std::cmp::min(br_stack.unwrap().nr * BR_ENTRY_SIZE, size);

            // 将 br_stack 中的条目复制到 buf 中
            std::ptr::copy_nonoverlapping(br_stack.unwrap().entries.as_ptr(), buf, to_copy as usize);

            // 返回复制的数据大小
            to_copy as i32
        }
    };
}

// 使用 BPF_CALL_4 宏定义 bpf_read_branch_records 函数
BPF_CALL_4!(bpf_read_branch_records, *mut bpf_perf_event_data_kern, *mut u8, u32, u64);