// 761-776
// BPF_CALL_0 宏的 Rust 实现
macro_rules! BPF_CALL_0 {
    ($func:ident) => {
        #[no_mangle]
        pub extern "C" fn $func() -> i64 {
            // 将 current 转换为 i64 类型并返回
            current as i64
        }
    };
}

// 使用 BPF_CALL_0 宏定义 bpf_get_current_task 函数
BPF_CALL_0!(bpf_get_current_task);

// 定义 bpf_func_proto 结构体
#[repr(C)]
pub struct bpf_func_proto {
    pub func: Option<extern "C" fn() -> i64>,
    pub gpl_only: bool,
    pub ret_type: i32,
}

// 定义 bpf_get_current_task_proto 常量
pub const bpf_get_current_task_proto: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_get_current_task),
    gpl_only: true,
    ret_type: 0, // 假设 RET_INTEGER 的值为 0
};

// 使用 BPF_CALL_0 宏定义 bpf_get_current_task_btf 函数
BPF_CALL_0!(bpf_get_current_task_btf);