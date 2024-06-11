uprobe_prog_run函数：
```rust
use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;

struct BpfUprobe {
    link: *mut BpfUprobeMultiLink,
    consumer: UprobeConsumer,
    cookie: u64,
}

struct BpfUprobeMultiLink {
    task: *mut TaskStruct,
    link: BpfLink,
}

struct BpfLink {
    prog: *mut BpfProg,
}

struct BpfUprobeMultiRunCtx {
    entry_ip: u64,
    uprobe: *mut BpfUprobe,
}

struct BpfRunCtx {
    // fields go here
}

extern "C" {
    fn current() -> *mut TaskStruct;
    fn bpf_set_run_ctx(ctx: *mut BpfRunCtx) -> *mut BpfRunCtx;
    fn bpf_reset_run_ctx(ctx: *mut BpfRunCtx);
    fn bpf_prog_run(prog: *mut BpfProg, regs: *mut PtRegs) -> i32;
    fn migrate_disable();
    fn migrate_enable();
    fn rcu_read_lock();
    fn rcu_read_unlock();
    fn rcu_read_lock_trace();
    fn rcu_read_unlock_trace();
}

unsafe fn uprobe_prog_run(uprobe: *mut BpfUprobe, entry_ip: u64, regs: *mut PtRegs) -> i32 {
    let link = (*uprobe).link;
    let run_ctx = BpfUprobeMultiRunCtx {
        entry_ip,
        uprobe,
    };
    let prog = (*link).link.prog;
    let sleepable = (*(*prog).aux).sleepable;
    let mut old_run_ctx: *mut BpfRunCtx;
    let mut err = 0;

    if !(*link).task.is_null() && current() != (*link).task {
        return 0;
    }

    if sleepable {
        rcu_read_lock_trace();
    } else {
        rcu_read_lock();
    }

    migrate_disable();

    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx as *const _ as *mut BpfRunCtx);
    err = bpf_prog_run((*link).link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);

    migrate_enable();

    if sleepable {
        rcu_read_unlock_trace();
    } else {
        rcu_read_unlock();
    }
    err
}
```
uprobe_multi_link_filter函数：

```rust
unsafe fn uprobe_multi_link_filter(con: *mut UprobeConsumer, _ctx: UprobeFilterCtx, mm: *mut MmStruct) -> bool {
    let uprobe = container_of(con, BpfUprobe, consumer);
    (*(*uprobe).link).task.mm == mm
}
```
uprobe_multi_link_handler函数：

```rust
unsafe fn uprobe_multi_link_handler(con: *mut UprobeConsumer, regs: *mut PtRegs) -> i32 {
    let uprobe = container_of(con, BpfUprobe, consumer);
    uprobe_prog_run(uprobe, instruction_pointer(regs), regs)
}
```
uprobe_multi_link_ret_handler函数：

```rust
unsafe fn uprobe_multi_link_ret_handler(con: *mut UprobeConsumer, func: u64, regs: *mut PtRegs) -> i32 {
    let uprobe = container_of(con, BpfUprobe, consumer);
    uprobe_prog_run(uprobe, func, regs)
}
```
bpf_uprobe_multi_entry_ip函数：

```rust
unsafe fn bpf_uprobe_multi_entry_ip(ctx: *mut BpfRunCtx) -> u64 {
    let run_ctx = container_of(current().bpf_ctx, BpfUprobeMultiRunCtx, run_ctx);
    (*run_ctx).entry_ip
}

bpf_uprobe_multi_cookie函数：
unsafe fn bpf_uprobe_multi_cookie(ctx: *mut BpfRunCtx) -> u64 {
    let run_ctx = container_of(current().bpf_ctx, BpfUprobeMultiRunCtx, run_ctx);
    (*run_ctx).uprobe.cookie
}