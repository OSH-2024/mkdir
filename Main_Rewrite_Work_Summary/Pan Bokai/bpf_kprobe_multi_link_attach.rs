//2945-3086
// bpf_kprobe_multi_link_attach 函数的 Rust 实现
fn bpf_kprobe_multi_link_attach(attr: &bpf_attr, prog: &mut bpf_prog) -> Result<(), i32> {
    // 检查系统是否支持 64 位架构
    if std::mem::size_of::<u64>() != std::mem::size_of::<*mut c_void>() {
        return Err(-EOPNOTSUPP);
    }

    // 检查程序的预期附加类型是否为 BPF_TRACE_KPROBE_MULTI
    if prog.expected_attach_type != BPF_TRACE_KPROBE_MULTI {
        return Err(-EINVAL);
    }

    // 获取 flags 并检查是否包含无效的标志位
    let flags = attr.link_create.kprobe_multi.flags;
    if flags & !BPF_F_KPROBE_MULTI_RETURN != 0 {
        return Err(-EINVAL);
    }

    // 获取用户空间的地址和符号指针,并检查是否同时提供了地址和符号
    let uaddrs = unsafe { attr.link_create.kprobe_multi.addrs.as_ptr() };
    let usyms = unsafe { attr.link_create.kprobe_multi.syms.as_ptr() };
    if (uaddrs.is_null() && usyms.is_null()) || (!uaddrs.is_null() && !usyms.is_null()) {
        return Err(-EINVAL);
    }

    // 获取 kprobe 的数量,并检查是否为 0 或超过最大值
    let cnt = attr.link_create.kprobe_multi.cnt;
    if cnt == 0 {
        return Err(-EINVAL);
    }
    if cnt > MAX_KPROBE_MULTI_CNT {
        return Err(-E2BIG);
    }

    // 分配内存用于存储地址和 cookie
    let size = cnt * std::mem::size_of::<*mut c_void>();
    let addrs = kvmalloc_array(cnt, std::mem::size_of::<*mut c_void>(), GFP_KERNEL)?;
    let mut cookies = None;

    // 获取用户空间的 cookie 指针
    let ucookies = unsafe { attr.link_create.kprobe_multi.cookies.as_ptr() };
    if !ucookies.is_null() {
        cookies = Some(kvmalloc_array(cnt, std::mem::size_of::<*mut c_void>(), GFP_KERNEL)?);
        if copy_from_user(cookies.as_mut().unwrap(), ucookies, size).is_err() {
            return Err(-EFAULT);
        }
    }

    // 从用户空间复制地址或符号到内核空间
    if !uaddrs.is_null() {
        if copy_from_user(addrs, uaddrs, size).is_err() {
            return Err(-EFAULT);
        }
    } else {
        let mut data = multi_symbols_sort {
            cookies: cookies.as_deref(),
            funcs: None,
        };
        let mut us = User_syms::default();

        if copy_user_syms(&mut us, usyms, cnt).is_err() {
            return Err(-EFAULT);
        }

        if cookies.is_some() {
            data.funcs = Some(us.syms.as_mut_ptr());
        }

        sort_r(us.syms.as_mut_ptr(), cnt, std::mem::size_of::<ksym>(), symbols_cmp_r, symbols_swap_r, &mut data);

        if ftrace_lookup_symbols(us.syms.as_mut_ptr(), cnt, addrs).is_err() {
            free_user_syms(&us);
            return Err(-EINVAL);
        }
        free_user_syms(&us);
    }

    // 如果程序启用了 kprobe 覆盖,则检查地址是否在错误注入列表中
    if prog.kprobe_override && addrs_check_error_injection_list(addrs, cnt).is_err() {
        return Err(-EINVAL);
    }

    // 分配并初始化 bpf_kprobe_multi_link 结构体
    let link = kzalloc(std::mem::size_of::<bpf_kprobe_multi_link>(), GFP_KERNEL)?;
    bpf_link_init(&mut link.link, BPF_LINK_TYPE_KPROBE_MULTI, &bpf_kprobe_multi_link_lops, prog);

    // 准备 link 结构体
    let mut link_primer = std::mem::MaybeUninit::uninit();
    if bpf_link_prime(&mut link.link, link_primer.as_mut_ptr()).is_err() {
        return Err(-EINVAL);
    }

    // 设置 link 的处理函数
    if flags & BPF_F_KPROBE_MULTI_RETURN != 0 {
        link.fp.exit_handler = Some(kprobe_multi_link_exit_handler);
    } else {
        link.fp.entry_handler = Some(kprobe_multi_link_handler);
    }

    // 设置 link 的其他字段
    link.addrs = addrs;
    link.cookies = cookies;
    link.cnt = cnt;
    link.flags = flags;

    // 如果提供了 cookie,则对地址和 cookie 进行排序
    if let Some(cookies) = &mut link.cookies {
        sort_r(addrs, cnt, std::mem::size_of::<*mut c_void>(), bpf_kprobe_multi_cookie_cmp, bpf_kprobe_multi_cookie_swap, link);
    }

    // 获取地址对应的模块
    match get_modules_for_addrs(&mut link.mods, addrs, cnt) {
        Ok(mods_cnt) => link.mods_cnt = mods_cnt,
        Err(err) => {
            bpf_link_cleanup(link_primer.as_mut_ptr());
            return Err(err);
        }
    }

    // 注册 kprobe
    if register_fprobe_ips(&mut link.fp, addrs, cnt).is_err() {
        kprobe_multi_put_modules(link.mods, link.mods_cnt);
        bpf_link_cleanup(link_primer.as_mut_ptr());
        return Err(-EINVAL);
    }

    // 完成 link 的创建
    bpf_link_settle(link_primer.as_mut_ptr())
}