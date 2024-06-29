// int bpf_uprobe_multi_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
// {
// 	return -EOPNOTSUPP;
// }
// static u64 bpf_uprobe_multi_cookie(struct bpf_run_ctx *ctx)
// {
// 	return 0;
// }
// static u64 bpf_uprobe_multi_entry_ip(struct bpf_run_ctx *ctx)
// {
// 	return 0;
// }

fn bpf_uprobe_multi_link_attach(attr: &bpf_attr, prog: &bpf_prog) -> i32 {
    return -EOPNOTSUPP;
}   

fn bpf_uprobe_multi_cookie(ctx: &bpf_run_ctx) -> u64 {
    return 0;
}

fn bpf_uprobe_multi_entry_ip(ctx: &bpf_run_ctx) -> u64 {
    return 0;
}   
