use std::os::raw::c_ulong;

#[cfg(not(feature = CONFIG_FPROBE))]

fn bpf_kprobe_multi_link_attach(attr: *union bpf_attr, prog: *mut bpf_prog) -> i32 
{
    return -EOPNOTSUPP;
}

fn  bpf_kprobe_multi_cookie(ctx: *mut bpf_run_ctx) -> u64
{
    return 0;
}

fn bpf_kprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    return 0;
}


#[cfg(feature = CONFIG_UPROBES)]
struct bpf_uprobe_multi_link;

struct bpf_uprobe 
{
    link: *mut bpf_uprobe_multi_link,
    offset: loff_t,
    ref_ctr_offset: c_ulong,
    cookie: u64,
    consumer: uprobe_consumer
}

struct bpf_uprobe_multi_link 
{
    path: path,
    link: bpf_link,
    cnt: u32,
    flags: u32,
    uprobes: *mut bpf_uprobe,
    task: *mut task_struct
}

struct bpf_uprobe_multi_run_ctx 
{
    run_ctx: bpf_run_ctx,
    entry_ip: c_ulong,
    uprobe: *mut bpf_uprobe
}

fn bpf_uprobe_unregister(path: *mut path, uprobes: *mut bpf_uprobe, cnt: u32)
{
    let mut i: u32 = 0;
    while i < cnt 
    {
        uprobe_unregister(d_real_inode(path.dentry), uprobes[i].offset, &uprobes[i].consumer);
        i += 1;
    }
}

fn bpf_uprobe_multi_link_release(link: *mut bpf_link)
{
    let umulti_link: *mut bpf_uprobe_multi_link = container_of(link, struct bpf_uprobe_multi_link, link);
    bpf_uprobe_unregister(&umulti_link.path, umulti_link.uprobes, umulti_link.cnt);
}

fn bpf_uprobe_multi_link_dealloc(link: *mut bpf_link)
{
    let umulti_link: *mut bpf_uprobe_multi_link = container_of(link, struct bpf_uprobe_multi_link, link);
    if umulti_link.task != 0
    {
        put_task_struct(umulti_link.task);
    }
    path_put(&umulti_link.path);
    kvfree(umulti_link.uprobes);
    kfree(umulti_link);
}

