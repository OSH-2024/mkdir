// 引入Rust的FFI（外部函数接口）功能，以便与C代码交互
// use std::os::raw::{c_int, c_void};

// 假设的外部Rust结构体和函数
// #[repr(C)]
// struct bpf_prog;
// 
// #[repr(C)]
// union bpf_attr;
// 
// extern "C" {
//     fn raw_tp_prog_func_proto() -> *const c_void;
//     fn raw_tp_prog_is_valid_access() -> c_int;
//     fn tracing_prog_func_proto() -> *const c_void;
//     fn tracing_prog_is_valid_access() -> c_int;
//     #[cfg(feature = "config_net")]
//     fn bpf_prog_test_run_raw_tp(prog: *const bpf_prog, kattr: *const bpf_attr, uattr: *mut bpf_attr) -> c_int;
// }

// 定义Rust版本的`bpf_prog_test_run_tracing`函数
// 使用`__weak`标记的C函数在Rust中没有直接等价物，但可以通过条件编译或其他机制模拟
#[no_mangle] // 确保函数名在编译后不会被改变，以便C代码可以找到它
pub extern "C" fn bpf_prog_test_run_tracing(prog: *const c_void, kattr: *const c_void, uattr: *mut c_void) -> c_int {
    // 返回-ENOTSUPP错误码，表示不支持的操作
    // 假设-ENOTSUPP为-95，实际值应根据具体环境确定
    -95
}

// 定义Rust版本的`bpf_verifier_ops`和`bpf_prog_ops`结构体
#[repr(C)]
struct bpf_verifier_ops {
    get_func_proto: extern "C" fn() -> *const c_void,
    is_valid_access: extern "C" fn() -> c_int,
}

#[repr(C)]
struct bpf_prog_ops {
    // 使用`Option`来处理可能不存在的函数指针
    test_run: Option<extern "C" fn(prog: *const c_void, kattr: *const c_void, uattr: *mut c_void) -> c_int>,
}

// 实例化`bpf_verifier_ops`和`bpf_prog_ops`结构体
static RAW_TRACEPOINT_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    get_func_proto: raw_tp_prog_func_proto,
    is_valid_access: raw_tp_prog_is_valid_access,
};

static RAW_TRACEPOINT_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
    // 使用条件编译来处理可选的函数指针
    #[cfg(feature = "config_net")]
    test_run: Some(bpf_prog_test_run_raw_tp),
    #[cfg(not(feature = "config_net"))]
    test_run: None,
};

static TRACING_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    get_func_proto: tracing_prog_func_proto,
    is_valid_access: tracing_prog_is_valid_access,
};

static TRACING_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
    test_run: Some(bpf_prog_test_run_tracing),
};