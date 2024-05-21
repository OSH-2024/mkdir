//361-371
// bpf_get_probe_write_proto 函数的 Rust 实现
fn bpf_get_probe_write_proto() -> Option<&'static BpfFuncProto> {
    // 检查是否具有 CAP_SYS_ADMIN 权限
    if !capable(CAP_SYS_ADMIN) {
        return None;
    }

    // 输出警告信息,提示正在安装可能损坏用户内存的程序
    pr_warn_ratelimited!(
        "{} is installing a program with bpf_probe_write_user helper that may corrupt user memory!",
        format!("{}[{}]", current().comm(), current().pid())
    );

    // 返回 bpf_probe_write_user_proto 的不可变引用
    Some(&BPF_PROBE_WRITE_USER_PROTO)
}