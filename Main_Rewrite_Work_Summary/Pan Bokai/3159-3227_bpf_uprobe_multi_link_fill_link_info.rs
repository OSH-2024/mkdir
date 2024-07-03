//3159-3227
// bpf_uprobe_multi_link_fill_link_info 函数的 Rust 实现
fn bpf_uprobe_multi_link_fill_link_info(link: &bpf_link, info: &mut bpf_link_info) -> Result<(), i32> {
    // 获取用户空间的引用计数器偏移、cookie 和偏移量指针
    let uref_ctr_offsets = unsafe { info.uprobe_multi.ref_ctr_offsets.as_ptr() };
    let ucookies = unsafe { info.uprobe_multi.cookies.as_ptr() };
    let uoffsets = unsafe { info.uprobe_multi.offsets.as_ptr() };
    let upath = unsafe { info.uprobe_multi.path.as_ptr() };
    let mut upath_size = info.uprobe_multi.path_size;
    let mut ucount = info.uprobe_multi.count;

    // 检查路径和路径大小的有效性
    if (upath.is_null() && upath_size != 0) || (!upath.is_null() && upath_size == 0) {
        return Err(-EINVAL);
    }

    // 检查偏移量、引用计数器偏移和 cookie 指针的有效性
    if ((!uoffsets.is_null() || !uref_ctr_offsets.is_null() || !ucookies.is_null()) && ucount == 0) {
        return Err(-EINVAL);
    }

    // 获取 bpf_uprobe_multi_link 结构体
    let umulti_link = unsafe { &*(link as *const _ as *const bpf_uprobe_multi_link) };
    info.uprobe_multi.count = umulti_link.cnt;
    info.uprobe_multi.flags = umulti_link.flags;
    info.uprobe_multi.pid = if let Some(task) = umulti_link.task {
        task_pid_nr_ns(task, task_active_pid_ns(current()))
    } else {
        0
    };

    // 获取路径信息
    if !upath.is_null() {
        upath_size = min(upath_size, PATH_MAX as u32);

        let buf = kmalloc(upath_size as usize, GFP_KERNEL)?;
        let p = d_path(&umulti_link.path, buf, upath_size as usize);
        if p.is_err() {
            kfree(buf);
            return Err(p.unwrap_err());
        }
        let p = p.unwrap();
        upath_size = (buf.as_ptr() as usize + upath_size as usize - p.as_ptr() as usize) as u32;
        let left = unsafe { copy_to_user(upath, p.as_ptr(), upath_size as usize) };
        kfree(buf);
        if left != 0 {
            return Err(-EFAULT);
        }
        info.uprobe_multi.path_size = upath_size;
    }

    // 如果没有提供偏移量、cookie 和引用计数器偏移指针,则直接返回
    if uoffsets.is_null() && ucookies.is_null() && uref_ctr_offsets.is_null() {
        return Ok(());
    }

    // 检查用户提供的计数是否小于实际的探针数量
    let mut err = Ok(());
    if ucount < umulti_link.cnt {
        err = Err(-ENOSPC);
        ucount = umulti_link.cnt;
    }

    // 复制偏移量、引用计数器偏移和 cookie 到用户空间
    for i in 0..ucount {
        if !uoffsets.is_null() {
            if unsafe { put_user(umulti_link.uprobes[i as usize].offset, uoffsets.add(i as usize)) } {
                return Err(-EFAULT);
            }
        }
        if !uref_ctr_offsets.is_null() {
            if unsafe { put_user(umulti_link.uprobes[i as usize].ref_ctr_offset, uref_ctr_offsets.add(i as usize)) } {
                return Err(-EFAULT);
            }
        }
        if !ucookies.is_null() {
            if unsafe { put_user(umulti_link.uprobes[i as usize].cookie, ucookies.add(i as usize)) } {
                return Err(-EFAULT);
            }
        }
    }

    err
}