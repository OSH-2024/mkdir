//1688-1695
// 两个模块的 Rust 实现
// 定义 kprobe 验证器操作
const KPROBE_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    // 获取函数原型的函数指针
    get_func_proto: Some(kprobe_prog_func_proto),
    // 检查访问是否有效的函数指针
    is_valid_access: Some(kprobe_prog_is_valid_access),
};

const KPROBE_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
};

