// Rust版本的bpf_perf_event_output_tp函数
// 使用`unsafe`因为我们将要进行裸指针操作和调用C函数
unsafe fn bpf_perf_event_output_tp(tp_buff: *mut c_void, map: *mut BpfMap, flags: c_ulonglong, data: *mut c_void, size: c_ulonglong) -> i32 {
    // 将`tp_buff`转换为`**PtRegs`类型的裸指针，以便获取`struct pt_regs`的指针
    let regs = *(tp_buff as *mut *mut PtRegs);

    /*
     * `r1`指向perf tracepoint缓冲区，其中前8字节对bpf程序隐藏，
     * 并包含指向`struct pt_regs`的指针。从那里获取它，
     * 并内联调用相同的`bpf_perf_event_output()`帮助函数。
     */
    ____bpf_perf_event_output(regs, map, flags, data, size)
}