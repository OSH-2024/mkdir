//2603-2769
// 众多函数、模块的 Rust 实现
fn copy_user_syms(us: &mut user_syms, usyms: *const u64, cnt: u32) -> Result<(), i32> {
    // 分配内存用于存储符号指针数组
    let mut syms = kvmalloc_array(cnt as usize, std::mem::size_of::<*const u8>(), GFP_KERNEL)?;

    // 分配内存用于存储符号名称缓冲区
    let mut buf = kvmalloc_array(cnt as usize, KSYM_NAME_LEN, GFP_KERNEL)?;

    let mut p = buf;
    for i in 0..cnt {
        // 从用户空间获取符号地址
        let usymbol = unsafe { *usyms.offset(i as isize) };

        // 从用户空间复制符号名称到内核缓冲区
        let err = strncpy_from_user(p, usymbol as *const u8, KSYM_NAME_LEN);
        if err == KSYM_NAME_LEN {
            // 符号名称过长
            kvfree(syms);
            kvfree(buf);
            return Err(-E2BIG);
        } else if err < 0 {
            // 复制失败
            kvfree(syms);
            kvfree(buf);
            return Err(err);
        }

        // 将符号指针存储到符号指针数组中
        unsafe { *syms.offset(i as isize) = p };

        // 更新缓冲区指针
        p = unsafe { p.offset(err as isize + 1) };
    }

    // 更新用户符号结构体
    us.syms = syms;
    us.buf = buf;

    Ok(())
}

fn kprobe_multi_put_modules(mods: &[*mut module], cnt: u32) {
    // 遍历模块指针数组
    for i in 0..cnt as usize {
        // 获取当前模块指针
        let module = unsafe { &*mods[i] };
        // 释放模块引用计数
        module_put(module);
    }
}

fn free_user_syms(us: &mut user_syms) {
    // 释放符号指针数组的内存
    kvfree(us.syms);
    // 释放符号名称缓冲区的内存
    kvfree(us.buf);
}

fn bpf_kprobe_multi_link_release(link: &mut bpf_link) {
    // 从 bpf_link 结构体中获取 bpf_kprobe_multi_link 结构体
    let kmulti_link = unsafe {
        &mut *(link as *mut bpf_link as *mut bpf_kprobe_multi_link)
    };

    // 注销 fprobe
    unregister_fprobe(&mut kmulti_link.fp);

    // 释放模块引用计数
    kprobe_multi_put_modules(&kmulti_link.mods, kmulti_link.mods_cnt);
}

fn bpf_kprobe_multi_link_dealloc(link: *mut bpf_link) {
    // 从 bpf_link 结构体中获取 bpf_kprobe_multi_link 结构体
    let kmulti_link = unsafe {
        &mut *(link as *mut bpf_kprobe_multi_link)
    };

    // 释放 kmulti_link.addrs 指向的内存
    kvfree(kmulti_link.addrs);

    // 释放 kmulti_link.cookies 指向的内存
    kvfree(kmulti_link.cookies);

    // 释放 kmulti_link.mods 指向的内存
    kfree(kmulti_link.mods);

    // 释放 kmulti_link 本身的内存
    kfree(kmulti_link as *mut bpf_kprobe_multi_link as *mut c_void);
}

fn bpf_kprobe_multi_link_fill_link_info(link: &bpf_link, info: &mut bpf_link_info) -> i32 {
    // 获取用户空间的地址数组和数组大小
    let uaddrs = info.kprobe_multi.addrs as *mut u64;
    let mut ucount = info.kprobe_multi.count;

    // 检查地址数组和数组大小的有效性
    if (uaddrs.is_null() && ucount != 0) || (!uaddrs.is_null() && ucount == 0) {
        return -EINVAL;
    }

    // 获取 bpf_kprobe_multi_link 结构体
    let kmulti_link = unsafe { &*(link as *const _ as *const bpf_kprobe_multi_link) };

    // 填充 bpf_link_info 结构体的相关字段
    info.kprobe_multi.count = kmulti_link.cnt;
    info.kprobe_multi.flags = kmulti_link.flags;
    info.kprobe_multi.missed = kmulti_link.fp.nmissed;

    // 如果用户空间没有提供地址数组,则直接返回
    if uaddrs.is_null() {
        return 0;
    }

    // 检查用户空间提供的数组大小是否足够
    if ucount < kmulti_link.cnt {
        ucount = kmulti_link.cnt;
        return -ENOSPC;
    }

    // 如果当前进程有权限查看符号值
    if kallsyms_show_value(current_cred()) {
        // 将内核空间的地址数组复制到用户空间
        if copy_to_user(uaddrs, kmulti_link.addrs, ucount * std::mem::size_of::<u64>()).is_err() {
            return -EFAULT;
        }
    } else {
        // 如果当前进程没有权限查看符号值,则将用户空间的地址数组填充为 0
        for i in 0..ucount {
            if put_user(0, uaddrs.offset(i as isize)).is_err() {
                return -EFAULT;
            }
        }
    }

    0
}

// 定义 BPF kprobe 多链接的操作函数集合
const bpf_kprobe_multi_link_lops: bpf_link_ops = bpf_link_ops {
    // 释放 BPF kprobe 多链接的资源
    release: Some(bpf_kprobe_multi_link_release),
    // 释放 BPF kprobe 多链接占用的内存
    dealloc: Some(bpf_kprobe_multi_link_dealloc),
    // 填充 BPF kprobe 多链接的相关信息
    fill_link_info: Some(bpf_kprobe_multi_link_fill_link_info),
};

fn bpf_kprobe_multi_cookie_swap(a: *mut c_void, b: *mut c_void, size: i32, priv_data: *const c_void) {
    // 将 priv_data 转换为 bpf_kprobe_multi_link 结构体的不可变引用
    let link = unsafe { &*(priv_data as *const bpf_kprobe_multi_link) };

    // 将 a 和 b 转换为可变的 unsigned long 指针
    let addr_a = a as *mut u64;
    let addr_b = b as *mut u64;

    // 计算 cookie_a 和 cookie_b 的位置
    let cookie_a = unsafe {
        link.cookies.offset((addr_a as usize - link.addrs as usize) / std::mem::size_of::<u64>())
    };
    let cookie_b = unsafe {
        link.cookies.offset((addr_b as usize - link.addrs as usize) / std::mem::size_of::<u64>())
    };

    // 交换 addr_a 和 addr_b 的值
    unsafe {
        std::ptr::swap(addr_a, addr_b);
    }

    // 交换 cookie_a 和 cookie_b 的值
    unsafe {
        std::ptr::swap(cookie_a, cookie_b);
    }
}

fn bpf_kprobe_multi_addrs_cmp(a: *const c_void, b: *const c_void) -> i32 {
    // 将 a 和 b 转换为不可变的 unsigned long 指针
    let addr_a = unsafe { &*(a as *const u64) };
    let addr_b = unsafe { &*(b as *const u64) };

    // 比较 addr_a 和 addr_b 的值
    if *addr_a == *addr_b {
        // 如果相等,返回 0
        0
    } else if *addr_a < *addr_b {
        // 如果 addr_a 小于 addr_b,返回 -1
        -1
    } else {
        // 如果 addr_a 大于 addr_b,返回 1
        1
    }
}

fn bpf_kprobe_multi_cookie_cmp(a: *const c_void, b: *const c_void, priv_data: *const c_void) -> i32 {
    // 调用 bpf_kprobe_multi_addrs_cmp 函数比较地址的大小关系
    bpf_kprobe_multi_addrs_cmp(a, b)
}

fn bpf_kprobe_multi_cookie(ctx: *mut bpf_run_ctx) -> u64 {
    // 检查 ctx 是否为空指针
    if ctx.is_null() {
        warn_on_once(true);
        return 0;
    }

    // 获取当前线程的 bpf_kprobe_multi_run_ctx
    let run_ctx = unsafe {
        &mut *(current.bpf_ctx as *mut bpf_kprobe_multi_run_ctx)
    };

    // 获取 bpf_kprobe_multi_link
    let link = run_ctx.link;

    // 如果 link 的 cookies 为空,则返回 0
    if link.cookies.is_null() {
        return 0;
    }

    // 获取 entry_ip
    let entry_ip = run_ctx.entry_ip;

    // 在 link 的 addrs 中二分查找 entry_ip
    let addr = unsafe {
        bsearch(
            &entry_ip,
            link.addrs,
            link.cnt as usize,
            std::mem::size_of::<u64>(),
            bpf_kprobe_multi_addrs_cmp,
        )
    };

    // 如果未找到对应的地址,则返回 0
    if addr.is_null() {
        return 0;
    }

    // 计算 cookie 的位置
    let cookie = unsafe {
        link.cookies.offset((addr as usize - link.addrs as usize) / std::mem::size_of::<u64>())
    };

    // 返回 cookie 的值
    unsafe { *cookie }
}