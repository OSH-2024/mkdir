//372-398
// BPF_CALL_5 宏的 Rust 实现
macro_rules! BPF_CALL_5 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(fmt: *const c_char, fmt_size: u32, arg1: u64, arg2: u64, arg3: u64) -> i64 {
            // 将参数存储在数组中
            let args: [u64; MAX_TRACE_PRINTK_VARARGS] = [arg1, arg2, arg3];
            
            // 创建 BpfBprintfData 结构体
            let mut data = BpfBprintfData {
                get_bin_args: true,
                get_buf: true,
                buf: [0; MAX_BPRINTF_BUF],
                bin_args: [0; MAX_BPRINTF_BIN_ARGS],
            };

            // 调用 bpf_bprintf_prepare 函数准备数据
            let ret = bpf_bprintf_prepare(fmt, fmt_size, &args, MAX_TRACE_PRINTK_VARARGS, &mut data);
            if ret < 0 {
                return ret;
            }

            // 调用 bstr_printf 函数进行格式化输出
            let ret = bstr_printf(&mut data.buf, MAX_BPRINTF_BUF, fmt, &data.bin_args);

            // 调用 trace_bpf_trace_printk 函数输出跟踪信息
            trace_bpf_trace_printk(&data.buf);

            // 调用 bpf_bprintf_cleanup 函数清理数据
            bpf_bprintf_cleanup(&mut data);

            ret
        }
    };
}