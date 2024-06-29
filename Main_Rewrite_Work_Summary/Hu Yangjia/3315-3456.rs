// 对于所有结构体，声明一个为使用Option类型来表示一个可能为空的值，类似于C语言中的NULL对象。具体来说，你可以这样声明一个结构体或者其他类型的字段，使其能够接受空值
// 名称为my_field_null

use std::os::raw::c_ulong;// 导入unsigned long类型
use std::ptr;// 导入指针类型
use libc::pid_t;// 导入pid_t类型
use std::mem;// 导入mem模块

extern "C" {
    fn u64_to_user_ptr(u64: u64) -> *mut std::ffi::c_void;
    fn strndup_user(u64: u64, size: usize) -> *mut c_char;
    fn IS_ERR(ptr: *mut c_void) -> bool;
    fn PTR_ERR(ptr: *mut c_void) -> i32;
    fn kern_path(name: *mut c_char, flags: i32, path: *mut path) -> i32;
    fn kfree(name: *mut c_char);
    fn d_is_reg(dentry: *mut dentry) -> bool;
    fn get_pid_task(pid: pid_t, pidtype: i32) -> *mut task_struct;
    fn find_vpid(pid: pid_t) -> pid_t;
    fn rcu_read_lock();
    fn rcu_read_unlock();
    fn kvcalloc(cnt: u32, size: usize, flags: u32) -> *mut std::ffi::c_void;
    fn kzalloc(size: usize, flags: u32) -> *mut std::ffi::c_void;

}

fn bpf_uprobe_multi_link_attach(attr: &bpf_attr, prog: &bpf_prog) -> i32 
{
    let mut link: Box<bpf_uprobe_multi_link> = Box::new(bpf_uprobe_multi_link::new());
    let mut uref_ctr_offsets = *mut c_ulong = std::ptr::null_mut();
    let link_primer = bpf_link_primer
    {
        my_field_null: None,
    };
    let mut uprobes: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    let mut task: Box<task_struct> = Box::new(task_struct::new());
    let mut uoffsets = *mut c_ulong = std::ptr::null_mut();
    let mut ucookies = *mut u64 = std::ptr::null_mut();
    let mut upath = std::ptr::void = std::ptr::null_mut();
    let mut flags:u32 = 0;
    let mut cint :u32 = 0;
    let mut i    :u32 = 0;
    let mut path = path::new();
    let mut name = *mut c_char = std::ptr::null_mut();
    let mut pid:pid_t;
    let mut err:i32;
    let mut signal:i32 = 0;

'error_dealing':loop{
    // 3331-3340
    if(mem::sizeof::<u64>() != mem::size_of::<*const std::ffi::c_void>())
    {
        return -EOPNOTSUPP;
    }
    if(prog.expected_attach_type != BPF_TRACE_UPROBE_MULTI)
    {
        return -EINVAL;
    }
    flags = attr.link_create.uprobe_multi.flags;
    if(flags & !BPF_UPROBE_MULTI_FLAG_MASK)
    {
        return -EINVAL;
    }

    // 3346-3388
    upath = u64_to_user_ptr(attr.link_create.uprobe_multi.path);
    uoffsets = u64_to_user_ptr(attr.link_create.uprobe_multi.offsets);
    cnt = attr.link_create.uprobe_multi.cnt;

    if(!upath || !uoffsets || !cnt)
    {
        return -EINVAL;
    }
    if(cnt > MAX_UPROBE_MULTI_CNT)
    {
        return -E2BIG;
    }
    uref_ctr_offsets = u64_to_user_ptr(attr.link_create.uprobe_multi.ref_ctr_offsets);
    ucookies = u64_to_user_ptr(attr.link_create.uprobe_multi.cookies);

    name = strndup_user(upath, PATH_MAX);
    if(IS_ERR(name))
    {
        err = PTR_ERR(name);
        return err;
    }

    err = kern_path(name, LOOKUP_FOLLOW, *mut path:*mut path);
    kfree(name);
    if(err)
    {
        return err;
    }
    if(!d_is_reg(path.dentry))
    {
        err = -EBADF;
        signal = 1;
        // goto error_path_put;
        break 'error_dealing';
    }
    pid = attr.link_create.uprobe_multi.pid;
    if(pid)
    {
        rcu_read_lock();
        task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
        rcu_read_unlock();
        if(!task)
        {
            err = -ESRCH;
            signal = 1;
            // goto error_path_put;
            break 'error_dealing';
        }
    }
    err = -ENOMEM;
    link = kzalloc(mem::size_of::<*const link>(), GFP_KERNEL);
    uprobes = kvcalloc(cnt, mem::size_of::<*const uprobes>(), GFP_KERNEL);

    // 3390-3420
    if(!uprobes || !link)
    {
        signal = 2;
        // goto error_free;
        break 'error_dealing';
    }
    for (i = 0; i < cnt; i++)
    {
        if(__get_user(uprobes[i].offset, uoffsets + i))
        {
            err = -EFAULT;
            signal = 2;
            // goto error_free;
            break 'error_dealing';
        }
        if (uprobes[i].offset < 0) {
			err = -EINVAL;
			signal = 2;
            // goto error_free;
            break 'error_dealing';
		}
        if (uref_ctr_offsets && __get_user(uprobes[i].ref_ctr_offset, uref_ctr_offsets + i)) {
			err = -EFAULT;
			signal = 2;
            // goto error_free;
            break 'error_dealing';
		}
		if (ucookies && __get_user(uprobes[i].cookie, ucookies + i)) {
			err = -EFAULT;
			signal = 2;
            // goto error_free;
            break 'error_dealing';
		}
        uprobes[i].link = link;
        if(flags & BPF_UPROBE_MULTI_FLAG_PRIME)
        {
            uprobes[i].link_primer = uprobe_multi_link_ret_handler;
        }
        else
        {
            uprobes[i].link_primer = uprobe_multi_link_handler;
        }
        if(pid)
        {
			uprobes[i].consumer.filter = uprobe_multi_link_filter;
        }
    }


    // 3422-3446
    link.cnt = cnt;
    link.uprobes = uprobes;
    link.path = path;
    link.task = task;
    link.flags = flags;

    bpf_link_init(*mut link.link:*mut link, BPF_TRACE_UPROBE_MULTI, &bpf_uprobe_multi_link_lops, prog);
    for (i = 0; i < cnt; i++)
    {
        err = uprobe_register_refctr(d_real_inode(link.path.dentry), uprobes[i].offset, uprobes[i].ref_ctr_offset, *mut uprobes[i].consumer);
        if(err)
        {
            bpf_uprobe_unregister(*mut path: *mut path, uprobes, i);
            signal = 2;
            // goto error_free;
            break 'error_dealing';
        }
    }
    err = bpf_link_prime(*mut link.link: *mut link, *mut link_primer);
    if(err)
    {
        signal = 2;
        // goto error_free;
        break 'error_dealing';
    }
    return bpf_link_settle(*mut link_primer);

}
    //3448-3456
    if(signal != 0)
    {
        if(signal == 2)
        {
            kvfree(uprobes);
            kfree(link);
            if(task)
            {
                put_task_struct(task);
            }
        }
        path_put(path);
        return err;
    }
}