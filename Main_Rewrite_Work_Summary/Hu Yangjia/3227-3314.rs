use lazy_static::lazy_static;
use std::os::raw::c_ulong;

// 全局变量，使用 lazy_static 宏和 Mutex 来保证线程安全
lazy_static! 
{
    static ref bpf_uprobe_multi_link_lops: Mutex<bpf_link_ops> = Mutex::new(bpf_link_ops 
    {
        release: bpf_uprobe_multi_link_release,
        dealloc: bpf_uprobe_multi_link_dealloc,
        fill_link_info: bpf_uprobe_multi_link_fill_link_info,
    });
}

fn uprobe_prog_run(*mut uprobe: *mut bpf_uprobe,
                    entry_ip: c_ulong,
                   *mut regs: *mut pt_regs) -> i32
{
    let mut link: *mut bpf_uprobe_multi_link = (*uprobe).link;
    let mut run_ctx:  bpf_uprobe_multi_run_ctx = bpf_uprobe_multi_run_ctx
    {
        entry_ip: entry_ip,
        uprobe: uprobe,
    };
    let mut prog: *mut bpf_prog = link.link.prog;
    let mut sleepable: bool = prog.aux.sleepable;
    let mut old_run_ctx:Box<bpf_run_ctx> = Box::new(bpf_run_ctx::new());
    let mux err: i32 = 0;

    if(link.task && current != link.task)
    {
        return 0;
    }
    if(sleepable)
    {
        rcu_read_lock_trace();
    }
    else
    {
        rcu_read_lock();
    }
    migrate_disable();

    old_run_ctx = bpf_set_run_ctx(run_ctx.run_ctx);
    err = bpf_prog_run(link.link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);

    migrate_enable();

    if(sleepable)
    {
        rcu_read_unlock_trace();
    }
    else
    {
        rcu_read_unlock();
    }
    return err;
}

fn uprobe_multi_link_filter(con: *mut uprobe_consumer, ctx: enum uprobe_filter_ctx, mm: *mut mm_struct) -> bool
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe.link.task.mm == mm;
}

fn uprobe_multi_link_handler(con: *mut uprobe_consumer, regs: *mut pt_regs) -> i32
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, instruction_pointer(regs), regs);
}


fn uprobe_multi_link_ret_handler(con: *mut uprobe_consumer, func: c_ulong, regs: *mut pt_regs) -> i32
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, func, regs);
}

fn bpf_uprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    let mut run_ctx: *mut bpf_uprobe_multi_run_ctx = container_of(current.bpf_ctx, bpf_uprobe_multi_run_ctx, run_ctx);
    return run_ctx.entry_ip;
}

fn bpf_uprobe_multi_cookie(ctx: *mut bpf_run_ctx) -> u64
{
    let mut run_ctx: *mut bpf_uprobe_multi_run_ctx = container_of(current.bpf_ctx, bpf_uprobe_multi_run_ctx, run_ctx);
    return run_ctx.uprobe.cookie;
}
