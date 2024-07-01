//2233-2346
// perf_event_attach_bpf_prog / perf_event_detach_bpf_prog / perf_event_query_prog_array函数的 Rust 实现
fn perf_event_attach_bpf_prog(
    event: &mut perf_event,
    prog: &mut bpf_prog,
    bpf_cookie: u64,
) -> i32 {
    let mut ret = -EEXIST;

    /*
     * Kprobe 覆盖只在函数入口处有效,
     * 并且只在选择加入列表中有效。
     */
    if prog.kprobe_override
        && (!trace_kprobe_on_func_entry(event.tp_event)
            || !trace_kprobe_error_injectable(event.tp_event))
    {
        return -EINVAL;
    }

    // 获取 bpf_event_mutex 的锁
    let _guard = bpf_event_mutex.lock();

    if event.prog.is_some() {
        ret = -EEXIST;
    } else {
        // 获取当前事件的程序数组
        let old_array = bpf_event_rcu_dereference(event.tp_event.prog_array.as_ref());
        if old_array.is_some()
            && bpf_prog_array_length(old_array.unwrap()) >= BPF_TRACE_MAX_PROGS
        {
            ret = -E2BIG;
        } else {
            // 复制旧的程序数组,并添加新的程序
            let mut new_array = None;
            ret = bpf_prog_array_copy(old_array, None, prog, bpf_cookie, &mut new_array);
            if ret >= 0 {
                // 设置新的程序数组到事件的 tp_event 中,并设置 event.prog
                event.prog = Some(prog);
                event.bpf_cookie = bpf_cookie;
                rcu_assign_pointer(event.tp_event.prog_array.as_mut(), new_array.as_ref());
                if let Some(old_array) = old_array {
                    bpf_prog_array_free_sleepable(old_array);
                }
            }
        }
    }

    ret
}

fn perf_event_detach_bpf_prog(event: &mut perf_event) {
    // 获取 bpf_event_mutex 的锁
    let _guard = bpf_event_mutex.lock();

    if event.prog.is_none() {
        return;
    }

    // 获取当前事件的程序数组
    let old_array = bpf_event_rcu_dereference(event.tp_event.prog_array.as_ref());

    // 复制旧的程序数组,并移除指定的 BPF 程序
    let mut new_array = None;
    let ret = bpf_prog_array_copy(old_array, event.prog, None, 0, &mut new_array);

    if ret == -ENOENT {
        // 如果指定的 BPF 程序不存在,则直接返回
        return;
    } else if ret < 0 {
        // 如果复制失败,则尝试从旧的程序数组中安全地删除指定的 BPF 程序
        if let Some(old_array) = old_array {
            bpf_prog_array_delete_safe(old_array, event.prog);
        }
    } else {
        // 如果复制成功,则将新的程序数组设置到事件的 tp_event 中
        rcu_assign_pointer(event.tp_event.prog_array.as_mut(), new_array.as_ref());
        if let Some(old_array) = old_array {
            bpf_prog_array_free_sleepable(old_array);
        }
    }

    // 释放指定的 BPF 程序,并将事件的 prog 字段设置为 None
    if let Some(prog) = event.prog.take() {
        bpf_prog_put(prog);
    }
}

fn perf_event_query_prog_array(event: &perf_event, info: *mut c_void) -> i32 {
    // 将 info 转换为 perf_event_query_bpf 类型的可变引用
    let uquery = info as *mut perf_event_query_bpf;
    let mut query = perf_event_query_bpf::default();

    // 检查权限
    if !perfmon_capable() {
        return -EPERM;
    }

    // 检查事件类型
    if event.attr.type_ != PERF_TYPE_TRACEPOINT {
        return -EINVAL;
    }

    // 从用户空间复制查询信息
    if copy_from_user(&mut query, uquery, std::mem::size_of::<perf_event_query_bpf>()).is_err() {
        return -EFAULT;
    }

    let ids_len = query.ids_len;
    // 检查查询的程序数量是否超过限制
    if ids_len > BPF_TRACE_MAX_PROGS {
        return -E2BIG;
    }

    // 分配内存用于存储程序 ID
    let ids = kcalloc(ids_len as usize, std::mem::size_of::<u32>(), GFP_USER | __GFP_NOWARN);
    if ids.is_null() {
        return -ENOMEM;
    }

    /*
     * 当 ids_len 为 0 时,上面的 kcalloc 会返回 ZERO_SIZE_PTR,
     * 这是用户只想检查 uquery->prog_cnt 所需的。
     * 不需要对此进行检查,因为在 bpf_prog_array_copy_info 中已经优雅地处理了这种情况。
     */

    let mut prog_cnt = 0;
    let ret = {
        // 获取 bpf_event_mutex 的锁
        let _guard = bpf_event_mutex.lock();
        let progs = bpf_event_rcu_dereference(event.tp_event.prog_array.as_ref());
        // 复制程序信息
        bpf_prog_array_copy_info(progs, ids, ids_len as usize, &mut prog_cnt)
    };

    // 将程序数量和 ID 复制回用户空间
    if copy_to_user(&mut (*uquery).prog_cnt, &prog_cnt, std::mem::size_of::<u32>()).is_err() ||
        copy_to_user((*uquery).ids, ids, (ids_len * std::mem::size_of::<u32>()) as usize).is_err()
    {
        kfree(ids);
        return -EFAULT;
    }

    kfree(ids);
    ret
}