use std::os::raw::c_ulong;

fn bpf_kprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    let run_ctx: *mut bpf_kprobe_multi_run_ctx = container_of((*ctx).bpf_ctx, bpf_kprobe_multi_run_ctx, run_ctx);
    return (*run_ctx).entry_ip;
}

fn kprobe_multi_link_prog_run(link: *mut bpf_kprobe_multi_link, entry_ip: c_ulong, regs: *mut pt_regs) -> i32
{
    let run_ctx: bpf_kprobe_multi_run_ctx = {
        .link = link,
        .entry_ip = entry_ip,
    };
    let old_run_ctx: *mut bpf_run_ctx;
    let err: i32;

'out' : loop {
    if((__this_cpu_inc_return(bpf_prog_active) != 1))
    {
        bpf_prog_inc_misses_counter((*link).link.prog);
        err = 0;
        break 'out';
    }

    migrate_disable();
    rcu_read_lock();
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    err = bpf_prog_run((*link).link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);
    rcu_read_unlock();
    migrate_enable();
}
    
    __this_cpu_dec(bpf_prog_active);
    return err;
}

static int
kprobe_multi_link_prog_run(struct bpf_kprobe_multi_link *link,
			   unsigned long entry_ip, struct pt_regs *regs)
{
	struct bpf_kprobe_multi_run_ctx run_ctx = {
		.link = link,
		.entry_ip = entry_ip,
	};
	struct bpf_run_ctx *old_run_ctx;
	int err;

	if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1)) {
		bpf_prog_inc_misses_counter(link->link.prog);
		err = 0;
		goto out;
	}

	migrate_disable();
	rcu_read_lock();
	old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
	err = bpf_prog_run(link->link.prog, regs);
	bpf_reset_run_ctx(old_run_ctx);
	rcu_read_unlock();
	migrate_enable();

 out:
	__this_cpu_dec(bpf_prog_active);
	return err;
}

fn kprobe_multi_link_handler(fp: *mut fprobe, fentry_ip: c_ulong, ret_ip: c_ulong, regs: *mut pt_regs, data: *mut c_void) -> i32
{
    let link: *mut bpf_kprobe_multi_link;

    link = container_of(fp, bpf_kprobe_multi_link, fp);
    kprobe_multi_link_prog_run(link, get_entry_ip(fentry_ip), regs);
    return 0;
}

fn kprobe_multi_link_exit_handler(fp: *mut fprobe, fentry_ip: c_ulong, ret_ip: c_ulong, regs: *mut pt_regs, data: *mut c_void)
{
    let link: *mut bpf_kprobe_multi_link;

    link = container_of(fp, bpf_kprobe_multi_link, fp);
    kprobe_multi_link_prog_run(link, get_entry_ip(fentry_ip), regs);
}

fn symbols_cmp_r(a: *const *const c_char, b: *const *const c_char, priv: *const c_void) -> i32
{
    let str_a: *const *const c_char = a;
    let str_b: *const *const c_char = b;

    return strcmp(*str_a, *str_b);
}

struct multi_symbols_sort
{
    funcs: *mut *mut c_char,
    cookies: *mut u64
}