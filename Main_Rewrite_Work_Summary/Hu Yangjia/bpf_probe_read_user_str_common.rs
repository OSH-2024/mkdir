use std::ptr;

extern "C"
{
    fn strncpy_from_user_nofault(dst: &mut [u8], unsafe_ptr: *const c_char, size: size_t) -> i32;
}
#[inline(always)]
use libc::{c_char, size_t, strncpy};
use std::ptr;

fn bpf_probe_read_user_str_common(dst: &mut [u8], unsafe_ptr: *const c_char, size: size_t) -> i32 {
    // 这个函数将复制用户空间中的字符串到内核空间
    // Rust 没有 `strncpy_from_user_nofault`，所以我们用类似方式来实现
    let ret: i32;

    unsafe {
        // 尝试复制字符串
        ret = strncpy_from_user_nofault(dst, unsafe_ptr, size);
    }

    if ret < 0 {
        // 如果复制失败，返回错误
        #[cold]
        // // 清空目标缓冲区
        // ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
        //清空dst对应的缓冲区
        ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());

        println!("Error: {}", ret); //测试代码
    }

    return ret;
}

fn main() {
    // 测试代码
    let mut buffer: [u8; 100] = [0; 100];
    let user_string = "Hello, user space!".as_ptr() as *const c_char;

    match bpf_probe_read_user_str_common(&mut buffer, user_string, 100) {
        Ok(size) => println!("Copied {} bytes: {:?}", size, &buffer[0..size]),
        Err(err) => println!("Error: {}", err),
    }
}
