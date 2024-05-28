// 252-277
#[inline(always)]
fn bpf_probe_read_kernel_str_common(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
    let mut ret: i32;

    /*
     * The strncpy_from_kernel_nofault() call will likely not fill the
     * entire buffer, but that's okay in this circumstance as we're probing
     * arbitrary memory anyway similar to bpf_probe_read_*() and might
     * as well probe the stack. Thus, memory is explicitly cleared
     * only in error case, so that improper users ignoring return
     * code altogether don't copy garbage; otherwise length of string
     * is returned that can be used for bpf_perf_event_output() et al.
     */

    // 调用 strncpy_from_kernel_nofault 函数将字符串从内核空间复制到目标缓冲区
    unsafe {
        ret = strncpy_from_kernel_nofault(dst, unsafe_ptr, size);
    }

    // 如果复制失败(返回值小于0),则将目标缓冲区清零
    if unlikely(ret < 0) {
        unsafe {
            core::ptr::write_bytes(dst, 0, size as usize);
        }
    }

    // 返回复制的字符串长度或错误码
    ret
}

// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
            // 调用 bpf_probe_read_kernel_str_common 函数
            bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr)
        }
    };
}

// 使用 BPF_CALL_3 宏定义 bpf_probe_read_kernel_str 函数
BPF_CALL_3!(bpf_probe_read_kernel_str, *mut u8, u32, *const u8);
