// 假设的外部类型和常量
// use std::os::raw::{c_void, c_ulong};

// BPF调用宏的Rust版本，用于获取函数的IP地址（用于追踪）
// 这个函数是一个内联函数，通常由验证器内联
unsafe fn bpf_get_func_ip_tracing(ctx: *const c_void) -> u64 {
    // 将传入的上下文（ctx）转换为一个指向u64的指针
    // 然后向后移动2个单位（因为ctx是一个指向栈顶的指针，我们需要获取调用函数的地址，通常位于栈顶以下两个位置）
    // 最后，通过解引用获取该位置的值，即函数的IP地址
    *((ctx as *const u64).offset(-2))
}