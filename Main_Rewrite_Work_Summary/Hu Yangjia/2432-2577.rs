use std::mem;
use std::os::raw::c_void;
use std::os::raw::c_char;
use std::os::raw::c_ulong;
use std::os::raw::c_int;
use std::sync::{Mutex, MutexGuard};


fn __bpf_probe_register(btp: *mut bpf_raw_event_map, prog: *mut bpf_prog) -> i32
{
    let tp: *mut tracepoint = btp.tp;
    if(prog.aux.max_ctx_offset > btp.num_args * mem::sizeof::<u64>())
    {
        return -EINVAL;
    }
    if(prog.aux.max_tp_access > btp.writable_size)
    {
        return -EINVAL;
    }
    return tracepoint_probe_register_may_exist(tp, btp.bpf_func as *mut c_void, prog);
}

fn bpf_probe_register(btp: *mut bpf_raw_event_map, prog: *mut bpf_prog) -> i32
{
    return __bpf_probe_register(btp, prog);
}

fn bpf_probe_unregister(btp: *mut bpf_raw_event_map, prog: *mut bpf_prog) -> i32
{
    return tracepoint_probe_unregister(btp.tp, btp.bpf_func as *mut c_void, prog);
}

fn bpf_get_perf_event_info(event: *const perf_event, prog_id: *mut u32, fd_type: *mut u32, buf: *mut *const c_char, probe_offset: *mut u64, probe_addr: *mut u64, missed: *mut c_ulong) -> i32
{
    let is_tracepoint: bool;
    let is_syscall_tp: bool;
    let prog: *mut bpf_prog;
    let flags: i32;
    let err: i32 = 0;

    prog = event.prog;
    if (!prog)
    {
        return -EINVAL;
    }
    if(prog,type == BPF_PROG_TYPE_PERF_EVENT)
    {
        return -EOPNOTSUPP;
    }
    *prog_id = prog.aux.id;
    flags = event.tp_event.flags;
    is_tracepoint = flags & TRACE_EVENT_FL_TRACEPOINT;
    is_syscall_tp = is_syscall_trace_event(event.tp_event);

    if(is_tracepoint || is_syscall_tp)
    {
        *buf = if is_tracepoint { event.tp_event.tp.name } else { event.tp_event.name };
        if(fd_type)
        {
            *fd_type = BPF_FD_TYPE_TRACEPOINT;
        }
        if(probe_offset)
        {
            *probe_offset = 0x0;
        }
        if(probe_addr)
        {
            *probe_addr = 0x0;
        }
    }
    else
    {
        err = -EOPNOTSUPP;
        #[cfg(feature = CONFIG_KPROBE_EVENTS)]
        if(flags & TRACE_EVENT_FL_UPROBE)
        {
            err = uprobe_perf_event_info(event, fd_type, buf, probe_offset, probe_addr, missed, event.attr,type == PERF_TYPE_TRACEPOINT);
        }
        #[cfg(feature = CONFIG_UPROBE_EVENTS)]
        if(flags & TRACE_EVENT_FL_UPROBE)
        {
            err = bpf_get_uprobe_info(event, fd_type, buf, probe_offset, probe_addr, misevent.attr,type == PERF_TYPE_TRACEPOINTsed);
        }
    }
    return err;
}

fn send_signal_irq_work_init() -> i32
{
    let cpu: i32;
    let work: *mut send_signal_irq_work;

    for_each_possible_cpu(cpu)
    {
        work = per_cpu_ptr(&send_signal_work, cpu);
        init_irq_work(&work.irq_work, do_bpf_send_signal);
    }
    return 0;
}

subsys_initcall(send_signal_irq_work_init);

#[cfg(feature = CONFIG_MODULES)]
fn bpf_event_notify(nb: *mut notifier_block, op: c_ulong, module: *mut c_void) -> i32
{
    let btm: *mut bpf_trace_module;
    let tmp: *mut bpf_trace_module;
    let mod: *mut module = module;
    let ret: i32 = 0;

'out':loop{
    if(mod.num_bpf_raw_events == 0 || (op != MODULE_STATE_COMING && op != MODULE_STATE_GOING))
    {
        break 'out';
    }
    let _lock: MutexGuard<'_, ()> = bpf_module_mutex.lock.unwrap();
    match op
    {
        MODULE_STATE_COMING => {
            btm = kzalloc(mem::size_of::<bpf_trace_module>(), GFP_KERNEL);
            if(btm)
            {
                btm.module = module;
                list_add(&btm.list, &bpf_trace_modules);
            }
            else
            {
                ret = -ENOMEM;
            }
        }
        MODULE_STATE_GOING => {
            list_for_each_entry_safe(btm, tmp, &bpf_trace_modules, list)
            {
                if(btm.module == module)
                {
                    list_del(&btm.list);
                    kfree(btm);
                    break;
                }
            }
        }
    }   

}
    return notifier_from_errno(ret);

}

let bpf_module_nb: notifier_block = notifier_block
{
    .notifier_call = bpf_event_notify,
};

fn bpf_module_init() -> i32
{
    register_module_notifier(&bpf_module_nb);
    return 0;
}

fs_initcall(bpf_event_init);