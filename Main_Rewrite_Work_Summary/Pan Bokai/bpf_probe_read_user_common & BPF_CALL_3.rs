//174-190
#[inline(always)]
fn bpf_probe_read_user_common(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
    let mut ret: i32;

    // 调用 copy_from_user_nofault 函数将数据从用户空间复制到内核空间
    unsafe {
        ret = copy_from_user_nofault(dst, unsafe_ptr, size);
    }

    // 如果复制失败(返回值小于0),则将目标缓冲区清零
    if unlikely(ret < 0) {
        unsafe {
            core::ptr::write_bytes(dst, 0, size as usize);
        }
    }

    ret
}

// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
            bpf_probe_read_user_common(dst, size, unsafe_ptr)
        }
    };
}

// 使用 BPF_CALL_3 宏定义 bpf_probe_read_user 函数
BPF_CALL_3!(bpf_probe_read_user, *mut u8, u32, *const u8);