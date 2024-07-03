use std::collections::LinkedList;
use std::sync::Mutex;
use std::ptr;
use libc::{c_char, size_t, strncpy};
use std::ffi::c_void;
use std::ptr::NonNull;
use std::io::{self, Write};
use std::os::raw::{ c_int, c_uint};
use core::cell::UnsafeCell;
// use kernel::THIS_MODULE;
// use kernel::prelude::*;


struct bpf_func_proto {
    func: extern "C" fn(*mut u32,...) -> u32, // 函数指针，接受一个可变参数列表，返回u32 // 函数指针，接受一个可变参数列表，返回u32
    ret_type: u32,                      // 返回类型
    gpl_only: bool,
    arg1_type: u32,                     // 第一个参数的类型
    arg2_type: u32,                     // 第二个参数的类型
    arg3_type: u32,                     // 第三个参数的类型
    arg4_type: u32,                     // 第四个参数的类型
    arg5_type: u32,                     // 第五个参数的类型
    arg1_btf_id : *const i32,           // 第一个参数的BTF ID
    ret_btf_id: *const i32,             // 返回值的BTF ID
    // 根据需要添加更多字段
}
struct bpf_bprintf_data {
    buffer: Vec<u8>,
    size: usize,
    capacity: usize,
    get_bin_args:bool,
}
#[repr(C)]
struct perf_sample_data {
    addr: u64,
    period: u64,
    context: Context,
    // 其他性能数据字段...
}

#[repr(C)]
struct Context {
    pid: u32,
    tid: u32,
}
//48-83


// Rust版本的`BpfTraceModule`结构体
// struct BpfTraceModule {
//     module: *mut Module,
//     // Rust中不需要显式地声明链表节点，因为`LinkedList`已经处理了
// }

// // Rust版本的全局变量和互斥锁
// lazy_static! {
//     static ref BPF_TRACE_MODULES: Mutex<LinkedList<BpfTraceModule>> = Mutex::new(LinkedList::new());
// }

// Rust版本的`bpf_get_raw_tracepoint_module`函数
fn bpf_get_raw_tracepoint_module(name: &str) -> Option<*mut BpfRawEventMap> {
    let bpf_module_mutex = BPF_TRACE_MODULES.lock().unwrap();
    for btm in bpf_module_mutex.iter() {
        let module = unsafe { &*btm.module }; // 不安全地解引用，因为我们正在处理裸指针
        for i in 0..module.num_bpf_raw_events {
            let btp = unsafe { &*module.bpf_raw_events.offset(i as isize) }; // 不安全地访问数组
            let tp_name = unsafe { CStr::from_ptr((*btp.tp).name) }; // 将C字符串转换为Rust字符串
            if tp_name.to_str().unwrap() == name {
                if unsafe { try_module_get(btm.module) } {
                    return Some(btp);
                } else {
                    break;
                }
            }
        }
    }
    None
}
//85-95
// 定义函数类型
type U64Func = fn(u64, u64, u64, u64, u64) -> u64;
type BpfRunCtx = *mut c_void;
type BtfPtr = *mut c_void;
type Btf = *const c_void;

// 定义函数
extern "C" {
    fn bpf_get_stackid(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;
    fn bpf_get_stack(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;

    fn bpf_kprobe_multi_cookie(ctx: BpfRunCtx) -> u64;
    fn bpf_kprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64;

    fn bpf_uprobe_multi_cookie(ctx: BpfRunCtx) -> u64;
    fn bpf_uprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64;
}
//96-110
// 文档注释：调用BPF程序的`trace_call_bpf`函数
// @call: tracepoint事件
// @ctx: 不透明的上下文指针
//
// kprobe处理程序通过此助手执行BPF程序。
// 将来可以从静态tracepoints中使用。
//
// 返回：BPF程序总是返回一个整数，kprobe处理程序将其解释为：
// 0 - 从kprobe返回（事件被过滤掉）
// 1 - 将kprobe事件存储到环形缓冲区中
// 其他值保留，当前与1相同
//111-156
// trace_call_bpf 函数的 Rust 实现
fn trace_call_bpf(call: &mut TraceEventCall, ctx: *mut c_void) -> u32 {
    let mut ret: u32;

    // 调用 cant_sleep 函数,表示当前上下文不能进入睡眠状态
    cant_sleep();

    // 使用 __this_cpu_inc_return 宏原子地增加 bpf_prog_active 的值,并判断是否不等于 1
    if unlikely(__this_cpu_inc_return(bpf_prog_active) != 1) {
        /*翻译部分：
         * 如果当前 CPU 上已经有其他 BPF 程序在运行,
         * 则不调用其他 BPF 程序(相同或不同),
         * 也不将 kprobe 事件发送到环形缓冲区,
         * 直接返回零
         */
        rcu_read_lock();
        bpf_prog_inc_misses_counters(rcu_dereference(call.prog_array));
        rcu_read_unlock();
        ret = 0;
        return ret;
    }

    /*翻译部分：
     * 为了避免在所有调用点移动 rcu_read_lock/rcu_dereference/rcu_read_unlock,
     * 我们在调用点使用 bpf_prog_array_valid() 检查 call->prog_array 是否为空,
     * 这是一种加速执行的启发式方法。
     *
     * 如果 bpf_prog_array_valid() 获取到的 prog_array 不为 NULL,
     * 我们进入 trace_call_bpf() 并在 RCU 锁下进行实际的 rcu_dereference()。
     * 如果发现 prog_array 为 NULL,则直接返回。
     * 相反,如果 bpf_prog_array_valid() 获取到的指针为 NULL,
     * 你将跳过 prog_array,但有可能在 rcu_dereference() 之前更新了 prog_array,
     * 这是可以接受的风险。
     */
    rcu_read_lock();
    ret = bpf_prog_run_array(rcu_dereference(call.prog_array), ctx, bpf_prog_run);
    rcu_read_unlock();

    // 使用 __this_cpu_dec 宏原子地减少 bpf_prog_active 的值
    __this_cpu_dec(bpf_prog_active);

    ret
}
//157-173


#[cfg(feature = CONFIG_BPF_KPROBE_OVERRIDE)]
unsafe fn bpf_override_return(regs: *mut pt_regs, rc: u64) -> i32 {
    regs_set_return_value(regs, rc);
    override_function_with_return(regs);
    0
}

static bpf_override_return_proto:bpf_func_proto = bpf_func_proto{
    func		: bpf_override_return,
    gpl_only	: true,
    ret_type	: RET_INTEGER,
    arg1_type	: ARG_PTR_TO_CTX,
    arg2_type	: ARG_ANYTHING,
    arg3_type: 0,
    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//174-190
#[inline(always)]
fn bpf_probe_read_user_common(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
    let mut ret: i32;

    // 调用 copy_from_user_nofault 函数将数据从用户空间复制到内核空间
    unsafe {
        ret = copy_from_user_nofault(dst, unsafe_ptr, size);
    }

    // 如果复制失败(返回值小于0),则将目标缓冲区清零
    if unlikely(ret < 0) {
        unsafe {
            core::ptr::write_bytes(dst, 0, size as usize);
        }
    }

    ret
}

// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
            bpf_probe_read_user_common(dst, size, unsafe_ptr)
        }
    };
}

// 使用 BPF_CALL_3 宏定义 bpf_probe_read_user 函数
BPF_CALL_3!(bpf_probe_read_user, *mut u8, u32, *const u8);
//191-199
static bpf_probe_read_user_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_probe_read_user, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,

    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//200-220


extern "C"
{
    fn strncpy_from_user_nofault(dst: &mut [u8], unsafe_ptr: *const c_char, size: size_t) -> i32;
}
#[inline(always)]


fn bpf_probe_read_user_str_common(dst: &mut [u8], unsafe_ptr: *const c_char, size: size_t) -> i32 {
    // 这个函数将复制用户空间中的字符串到内核空间
    // Rust 没有 `strncpy_from_user_nofault`，所以我们用类似方式来实现
    let ret: i32;

    unsafe {
        // 尝试复制字符串
        ret = strncpy_from_user_nofault(dst, unsafe_ptr, size);
    

        if ret < 0 {
            // 如果复制失败，返回错误
            #[cold]
            // // 清空目标缓冲区
            // ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
            //清空dst对应的缓冲区
            ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());

            println!("Error: {}", ret); //测试代码
        }
    }

    return ret;
}
//222-250

fn bpf_probe_read_user_str(dst: NonNull<c_void>,size: u32,unsafe_ptr:NonNull<c_void>) -> i32{
    unsafe{
        let ret = bpf_probe_read_user_str_common(dst.as_ptr(), size, unsafe_ptr.as_ptr());
        ret
    }
}
static bpf_probe_read_user_str_proto : bpf_func_proto = bpf_func_proto {
    func: bpf_probe_read_user_str, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,

    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
fn bpf_probe_read_kernel(dst: NonNull<c_void>,size: u32,unsafe_ptr:NonNull<c_void>) -> i32{
    let ret = bpf_probe_read_kernel_common(dst.as_ptr(), size, unsafe_ptr.as_ptr());
    ret
}
static bpf_probe_read_kernel_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_probe_read_kernel, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,

    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
// 252-277
#[inline(always)]
fn bpf_probe_read_kernel_str_common(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
    let mut ret: i32;

    /*
     * The strncpy_from_kernel_nofault() call will likely not fill the
     * entire buffer, but that's okay in this circumstance as we're probing
     * arbitrary memory anyway similar to bpf_probe_read_*() and might
     * as well probe the stack. Thus, memory is explicitly cleared
     * only in error case, so that improper users ignoring return
     * code altogether don't copy garbage; otherwise length of string
     * is returned that can be used for bpf_perf_event_output() et al.
     */

    // 调用 strncpy_from_kernel_nofault 函数将字符串从内核空间复制到目标缓冲区
    unsafe {
        ret = strncpy_from_kernel_nofault(dst, unsafe_ptr, size);
    }

    // 如果复制失败(返回值小于0),则将目标缓冲区清零
    if unlikely(ret < 0) {
        unsafe {
            core::ptr::write_bytes(dst, 0, size as usize);
        }
    }

    // 返回复制的字符串长度或错误码
    ret
}

// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(dst: *mut u8, size: u32, unsafe_ptr: *const u8) -> i32 {
            // 调用 bpf_probe_read_kernel_str_common 函数
            bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr)
        }
    };
}

// 使用 BPF_CALL_3 宏定义 bpf_probe_read_kernel_str 函数
BPF_CALL_3!(bpf_probe_read_kernel_str, *mut u8, u32, *const u8);

//278-285
static bpf_probe_read_kernel_str_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_probe_read_kernel_str, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_UNINIT_MEM,
    arg2_type: ArgType::ARG_CONST_SIZE_OR_ZERO,
    arg3_type: ArgType::ARG_ANYTHING,

    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//286-326


#[cfg(feature = CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE)]
// BPF_CALL_3(bpf_probe_read_compat, *mut c_void, dst, u32, size, *const c_void, unsafe_ptr) 
// {
//     if unsafe_ptr as usize < TASK_SIZE {
//         bpf_probe_read_user_common(dst, size, unsafe_ptr as *const _)
//     } 
//     else 
//     {
//         bpf_probe_read_kernel_common(dst, size, unsafe_ptr)
//     }
// }

unsafe fn bpf_probe_read_compat(dst:*mut c_void, size:u32 , unsafe_ptr:*const c_void)->i32{
    if unsafe_ptr  < TASK_SIZE{
        bpf_probe_read_user_common(dst,size,unsafe_ptr as *const _)
    }
    else{
        bpf_probe_read_kernel_common(dst,size,unsafe_ptr)
    }
}


static bpf_probe_read_compat_proto:bpf_func_proto=bpf_func_proto{
    func:bpf_probe_read_compat,
    gpl_only:true,
    ret_type:RET_INTEGER,
    arg1_type:ARG_PTR_TO_UNINIT_MEM,
    arg2_type:ARG_CONST_SIZE_OR_ZERO,
    arg3_type:ARG_ANYTHING,

    arg4_type:0,
    arg5_type:0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};

// BPF_CALL_3(bpf_probe_read_compat_str, *mut c_void, dst, u32, size, *mut c_void, unsafe_ptr)
// {
//     if (unsafe_ptr as usize< TASK_SIZE) 
//     {
//         return bpf_probe_read_user_str_common(dst, size, unsafe_ptr as *mut c_void);
//     }
//     return bpf_probe_read_kernel_str_common(dst, size, unsafe_ptr);
// }

static TASK_SIZE:u32 =16;
unsafe fn bpf_probe_read_compat_str(dst:*mut c_void,size:u32,unsafe_ptr:*mut c_void)->i32{
    if (unsafe_ptr  < TASK_SIZE) {
        bpf_probe_read_user_str_common(dst,size,unsafe_ptr as *mut c_void)
    }
    else{
        bpf_probe_read_kernel_str_common(dst,size,unsafe_ptr)
    }
}
static bpf_probe_read_compat_str_proto: bpf_func_proto=bpf_func_proto
{
    func:bpf_probe_read_compat_str,
    gpl_only:true,
    ret_type:RET_INTEGER,
    arg1_type:ARG_PTR_TO_UNINIT_MEM,
    arg2_type:ARG_CONST_SIZE_OR_ZERO,
    arg3_type:ARG_ANYTHING,

    arg4_type:0,
    arg5_type:0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//327-359

fn bpf_probe_write_user(unsafe_ptr:NonNull<c_void>,src:NonNull<c_void>,size:u32)->i32{
    unsafe{
        let in_interrupt_var = in_interrupt() as bool;
        let unlikely_var = unlikely(in_interrupt_var||current.flags & (PF_KTHREAD | PF_EXITING)) as bool;
        if unlikely_var{
            return -EPERM;
        }
        let nmi_uaccess_okay_var = nmi_uaccess_okay() as bool;
        let unlikely_var1 = unlikely(!nmi_uaccess_okay_var) as bool;
        if unlikely_var1{
            return -EPERM;
        }
        let copy_to_user_nofault_var=copy_to_user_nofault(unsafe_ptr.as_ptr(), src.as_ptr(), size);
    }
    copy_to_user_nofault_var
}
static bpf_probe_write_user_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_probe_write_user, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_ANYTHING,
    arg2_type: ArgType::ARG_PTR_TO_MEM | MEM_RDONLY,
    arg3_type: ArgType::ARG_CONST_SIZE,
    
    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//361-371
// bpf_get_probe_write_proto 函数的 Rust 实现
fn bpf_get_probe_write_proto() -> Option<&'static BpfFuncProto> {
    // 检查是否具有 CAP_SYS_ADMIN 权限
    if !capable(CAP_SYS_ADMIN) {
        return None;
    }

    // 输出警告信息,提示正在安装可能损坏用户内存的程序
    pr_warn_ratelimited!(
        "{} is installing a program with bpf_probe_write_user helper that may corrupt user memory!",
        format!("{}[{}]", current().comm(), current().pid())
    );

    // 返回 bpf_probe_write_user_proto 的不可变引用
    Some(&BPF_PROBE_WRITE_USER_PROTO)
}
//372-398
// BPF_CALL_5 宏的 Rust 实现
macro_rules! BPF_CALL_5 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(fmt: *const c_char, fmt_size: u32, arg1: u64, arg2: u64, arg3: u64) -> i64 {
            // 将参数存储在数组中
            let args: [u64; MAX_TRACE_PRINTK_VARARGS] = [arg1, arg2, arg3];
            
            // 创建 BpfBprintfData 结构体
            let mut data = BpfBprintfData {
                get_bin_args: true,
                get_buf: true,
                buf: [0; MAX_BPRINTF_BUF],
                bin_args: [0; MAX_BPRINTF_BIN_ARGS],
            };

            // 调用 bpf_bprintf_prepare 函数准备数据
            let ret = bpf_bprintf_prepare(fmt, fmt_size, &args, MAX_TRACE_PRINTK_VARARGS, &mut data);
            if ret < 0 {
                return ret;
            }

            // 调用 bstr_printf 函数进行格式化输出
            let ret = bstr_printf(&mut data.buf, MAX_BPRINTF_BUF, fmt, &data.bin_args);

            // 调用 trace_bpf_trace_printk 函数输出跟踪信息
            trace_bpf_trace_printk(&data.buf);

            // 调用 bpf_bprintf_cleanup 函数清理数据
            bpf_bprintf_cleanup(&mut data);

            ret
        }
    };
}
//399-405
pub struct BpfFuncProto {
    func: fn() -> (), // 这是一个函数指针，将来需要根据实际的函数签名进行修改
    gpl_only: bool,
    ret_type: RetType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
    arg1_type: ArgType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
    arg2_type: ArgType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
}

// // 将来需要根据实际情况定义这些类型
// pub enum RetType {
//     RetInteger,
//     // 其他返回类型
// }

// pub enum ArgType {
//     ArgPtrToMem,
//     ArgConstSize,
//     // 其他参数类型
// }
//407-420


fn set_printk_clr_event() -> io::Result<()> {
    /*
     * This program might be calling bpf_trace_printk,
     * so enable the associated bpf_trace/bpf_trace_printk event.
     * Repeat this each time as it is possible a user has
     * disabled bpf_trace_printk events.  By loading a program
     * calling bpf_trace_printk() however the user has expressed
     * the intent to see such events.
     */
    if trace_set_clr_event("bpf_trace", "bpf_trace_printk", 1)? {
        writeln!(io::stderr(), "could not enable bpf_trace_printk events");
    }
    Ok(())
}

// // 将来需要根据实际情况定义这个函数
// fn trace_set_clr_event(event1: &str, event2: &str, flag: i32) -> io::Result<bool> {
//     // 实现这个函数
//     Ok(false)
// }
//421-425
struct BpfFuncProto;

static mut BPF_TRACE_PRINTK_PROTO: BpfFuncProto = BpfFuncProto;

// fn set_printk_clr_event() {
//     // 这里是实现,在别的部分
// }

fn bpf_get_trace_printk_proto() -> &'static BpfFuncProto {
    set_printk_clr_event();
    unsafe { &BPF_TRACE_PRINTK_PROTO }
}
//426-452
// // 假设的常量，因为在原始C代码中这些值是从其他地方引入的
// const MAX_BPRINTF_VARARGS: usize = 16;
// const MAX_BPRINTF_BUF: usize = 1024;
// const EINVAL: i32 = -22;

// 用于存储打印数据的结构体
struct BpfBprintfData {
    get_bin_args: bool,
    get_buf: bool,
    buf: Vec<u8>, // 使用Vec<u8>作为缓冲区
    bin_args: Vec<u64>, // 假设参数是u64类型的数组
}

// // 假设的外部函数，用于格式化字符串
// fn bstr_printf(buf: &mut Vec<u8>, max_len: usize, fmt: &str, args: &[u64]) -> i32 {
//     // 这里只是一个示例，实际上需要根据fmt和args来格式化字符串
//     0 // 假设总是成功
// }

// // 假设的外部函数，用于打印跟踪信息
// fn trace_bpf_trace_printk(buf: &Vec<u8>) {
//     // 打印buf中的内容
// }

// // 假设的函数，用于准备打印数据
// fn bpf_bprintf_prepare(fmt: &str, fmt_size: u32, args: *const u64, num_args: usize, data: &mut BpfBprintfData) -> i32 {
//     // 这里只是一个示例，实际上需要根据fmt和args来准备数据
//     0 // 假设总是成功
// }

// Rust版本的bpf_trace_vprintk函数


unsafe fn bpf_trace_vprintk(fmt: &str, fmt_size: u32, args: *const u64, data_len: u32) -> i32 {
    let mut data = BpfBprintfData {
        get_bin_args: true,
        get_buf: true,
        buf: Vec::new(),
        bin_args: Vec::new(),
    };

    if data_len as usize % 8 != 0 || data_len as usize > MAX_BPRINTF_VARARGS * 8 || (data_len > 0 && args.is_null()) {
        return EINVAL;
    }
    let num_args = (data_len / 8) as usize;

    let ret = bpf_bprintf_prepare(fmt, fmt_size, args, num_args, &mut data);
    if ret < 0 {
        return ret;
    }

    let ret = bstr_printf(&mut data.buf, MAX_BPRINTF_BUF, fmt, &data.bin_args);
    trace_bpf_trace_printk(&data.buf);

    ret
}
//454-535
// 引入Rust标准库中的FFI（外部函数接口）相关功能


// 假设的外部结构体和函数
// extern "C" {
//     fn __set_printk_clr_event();
//     fn seq_write(m: *mut SeqFile, data: *const c_void, len: u32) -> bool;
//     fn seq_bprintf(m: *mut SeqFile, fmt: *const c_char, ...);
//     fn seq_has_overflowed(m: *mut SeqFile) -> bool;
//     fn bpf_bprintf_prepare(fmt: *const c_char, fmt_size: u32, args: *const c_void, num_args: i32, data: *mut BpfBprintfData) -> i32;
//     fn bpf_bprintf_cleanup(data: *mut BpfBprintfData);
//     fn btf_type_seq_show_flags(btf: *const Btf, btf_id: i32, ptr: *const c_void, m: *mut SeqFile, flags: u64) -> i32;
// }

// 常量定义
const MAX_BPRINTF_VARARGS: usize = 16;

// 结构体定义
#[repr(C)]
struct SeqFile;
// #[repr(C)]
// struct BpfBprintfData {
//     get_bin_args: bool,
//     // 其他字段...
// }
#[repr(C)]
struct BtfPtr;
#[repr(C)]
struct Btf;

// BPF函数原型结构体
#[repr(C)]
struct BpfFuncProto {
    func: unsafe extern "C" fn(),
    gpl_only: bool,
    ret_type: ReturnType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
    arg4_type: ArgType,
    // 对于具有更多参数的函数，可以继续添加字段
}

// 返回类型和参数类型的枚举
#[derive(Clone, Copy)]
enum ReturnType {
    Integer,
    // 其他返回类型...
}

#[derive(Clone, Copy)]
enum ArgType {
    PtrToMemReadOnly,
    ConstSize,
    PtrToMemMaybeNullReadOnly,
    ConstSizeOrZero,
    PtrToBtfId,
    // 其他参数类型...
}

// BPF函数实现
static BPF_TRACE_VPRINTK_PROTO: bpf_func_proto = bpf_func_proto {
    func: bpf_trace_vprintk as unsafe extern "C" fn(),
    gpl_only: true,
    ret_type: ReturnType::Integer,
    arg1_type: ArgType::PtrToMemReadOnly,
    arg2_type: ArgType::ConstSize,
    arg3_type: ArgType::PtrToMemMaybeNullReadOnly,
    arg4_type: ArgType::ConstSizeOrZero,

    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};

unsafe extern "C" fn bpf_trace_vprintk() {
    // 实现细节...
}

// 获取BPF函数原型
unsafe fn bpf_get_trace_vprintk_proto() -> &'static BpfFuncProto {
    __set_printk_clr_event();
    &BPF_TRACE_VPRINTK_PROTO
}

// BPF调用实现
unsafe extern "C" fn bpf_seq_printf(m: *mut SeqFile, fmt: *const c_char, fmt_size: c_uint, args: *const c_void, data_len: c_uint) -> c_int {
    let mut data = bpf_bprintf_data {
        get_bin_args: true,
        
        buffer : Vec::new(),
        size: 0,
        capacity: 0,
    };
    let num_args = data_len / 8;

    if data_len % 8 != 0 || data_len > MAX_BPRINTF_VARARGS as c_uint * 8 || (data_len > 0 && args.is_null()) {
        return -EINVAL;
    }

    let err = bpf_bprintf_prepare(fmt, fmt_size, args, num_args as i32, &mut data);
    if err < 0 {
        return err;
    }

    seq_bprintf(m, fmt, data.bin_args);

    bpf_bprintf_cleanup(&mut data);

    if seq_has_overflowed(m) {
        -EOVERFLOW
    } else {
        0
    }
}

// 其他函数和结构体定义类似地转换...
//537-546
// // 假设的外部函数和变量声明
// extern "C" {
//     fn bpf_seq_printf_btf(); // 假设的外部函数
//     static btf_seq_file_ids: [i32; 1]; // 假设的外部静态数组
// }

// 定义返回类型的枚举
#[derive(Debug, Clone, Copy)]
enum ReturnType {
    Integer, // 对应C代码中的RET_INTEGER
}

// 定义参数类型的枚举
#[derive(Debug, Clone, Copy)]
enum ArgType {
    PtrToBtfId, // 对应C代码中的ARG_PTR_TO_BTF_ID
    PtrToMemReadOnly, // 对应C代码中的ARG_PTR_TO_MEM | MEM_RDONLY
    ConstSizeOrZero, // 对应C代码中的ARG_CONST_SIZE_OR_ZERO
    Anything, // 对应C代码中的ARG_ANYTHING
}

// 定义BPF函数原型的结构体
#[repr(C)]
struct BpfFuncProto {
    func: unsafe extern "C" fn(), // 函数指针
    gpl_only: bool, // 是否仅GPL许可
    ret_type: ReturnType, // 返回类型
    arg1_type: ArgType, // 第一个参数的类型
    arg1_btf_id: *const i32, // 第一个参数的BTF ID指针
    arg2_type: ArgType, // 第二个参数的类型
    arg3_type: ArgType, // 第三个参数的类型
    arg4_type: ArgType, // 第四个参数的类型
}

// 实例化BPF函数原型
static BPF_SEQ_PRINTF_BTF_PROTO: bpf_func_proto = bpf_func_proto {
    func: bpf_seq_printf_btf, // 指向假设的外部函数
    gpl_only: true,
    ret_type: ReturnType::Integer,
    arg1_type: ArgType::PtrToBtfId,
    arg1_btf_id: unsafe { &btf_seq_file_ids[0] }, // 不安全代码块用于访问外部静态数组
    arg2_type: ArgType::PtrToMemReadOnly,
    arg3_type: ArgType::ConstSizeOrZero,
    arg4_type: ArgType::Anything,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//548-609
// // 假设的外部内容，用于提供必要的上下文
// const BPF_F_INDEX_MASK: u64 = 0x...; // 假设的掩码值
// const BPF_F_CURRENT_CPU: u64 = 0x...; // 表示当前CPU的特殊值
// const EINVAL: i32 = -22; // 无效参数错误码
// const E2BIG: i32 = -7; // 参数太大错误码
// const ENOENT: i32 = -2; // 没有该文件或目录的错误码

// // 假设的结构体和函数
// struct BpfMap {
//     // ...
// }

// struct BpfArray {
//     map: BpfMap,
//     ptrs: Vec<*mut BpfEventEntry>, // 使用裸指针，因为Rust不允许直接对应C的指针操作
//     // ...
// }

// struct BpfEventEntry {
//     event: *mut PerfEvent, // 假设的性能事件结构体指针
//     // ...
// }

struct BpfPerfEventValue {
    counter: u64,
    enabled: u64,
    running: u64,
}

// 假设的外部函数
// fn smp_processor_id() -> u32 { ... }
// fn perf_event_read_local(event: *mut PerfEvent, value: &mut u64, enabled: &mut u64, running: &mut u64) -> i32 { ... }
// fn memset(buf: &mut [u8], value: u8, size: usize) { ... }

// Rust中的内联总是使用`#[inline(always)]`属性
#[inline(always)]
fn get_map_perf_counter(map: &BpfMap, flags: u64, value: &mut u64, enabled: Option<&mut u64>, running: Option<&mut u64>) -> Result<(), i32> {
    // 使用`unsafe`块来调用不安全的操作，如裸指针解引用
    unsafe {
        let array = &*(map as *const _ as *const BpfArray); // 类型转换
        let cpu = smp_processor_id();
        let mut index = flags & BPF_F_INDEX_MASK;
        if flags & !BPF_F_INDEX_MASK != 0 {
            return Err(EINVAL);
        }
        if index == BPF_F_CURRENT_CPU {
            index = cpu as u64;
        }
        if index >= array.map.max_entries as u64 {
            return Err(E2BIG);
        }
        let ee = *array.ptrs.get(index as usize).ok_or(ENOENT)?;
        if ee.is_null() {
            return Err(ENOENT);
        }
        // 假设perf_event_read_local是安全的
        perf_event_read_local((*ee).event, value, enabled.unwrap_or(&mut 0), running.unwrap_or(&mut 0))?;
    }
    Ok(())
}

// 使用宏来模拟C中的宏定义函数
macro_rules! bpf_call {
    ($name:ident, $map:expr, $flags:expr, $buf:expr, $size:expr) => {
        match $name($map, $flags, $buf, $size) {
            Ok(_) => 0,
            Err(e) => e,
        }
    };
}

// Rust不支持直接的函数重载，所以使用不同的函数名
fn bpf_perf_event_read(map: &BpfMap, flags: u64) -> Result<u64, i32> {
    let mut value = 0;
    get_map_perf_counter(map, flags, &mut value, None, None)?;
    Ok(value)
}

fn bpf_perf_event_read_value(map: &BpfMap, flags: u64, buf: &mut BpfPerfEventValue, size: u32) -> Result<(), i32> {
    if size as usize != std::mem::size_of::<BpfPerfEventValue>() {
        // 使用Rust的内置函数来清零
        *buf = BpfPerfEventValue { counter: 0, enabled: 0, running: 0 };
        return Err(EINVAL);
    }
    get_map_perf_counter(map, flags, &mut buf.counter, Some(&mut buf.enabled), Some(&mut buf.running))
}
//610-654
// // 假设的外部内容，用于提供必要的上下文
// use std::ptr::NonNull;

// const BPF_F_INDEX_MASK: u64 = 0x...; // 假设的掩码值
// const BPF_F_CURRENT_CPU: u64 = 0x...; // 表示当前CPU的特殊值
// const E2BIG: i64 = -7; // 参数太大错误码
// const ENOENT: i64 = -2; // 没有该文件或目录的错误码
// const EINVAL: i64 = -22; // 无效参数错误码
// const EOPNOTSUPP: i64 = -95; // 操作不支持的错误码

// // 假设的结构体和函数
// struct PtRegs;
// struct BpfMap;
// struct PerfSampleData;
// struct PerfEvent;

struct BpfArray {
    map: BpfMap,
    ptrs: Vec<Option<NonNull<BpfEventEntry>>>,
}

struct BpfEventEntry {
    event: NonNull<PerfEvent>,
}

struct PerfEventAttr {
    type_: u32,
    config: u64,
}

struct PerfEvent {
    attr: PerfEventAttr,
    oncpu: u32,
}

// 假设的外部函数
// fn container_of!(...) -> ... { ... }
// fn smp_processor_id() -> u32 { ... }
// fn perf_event_output(event: &PerfEvent, sd: &PerfSampleData, regs: &PtRegs) -> i64 { ... }

// Rust中的函数原型定义
struct BpfFuncProto {
    func: fn(&BpfMap, u64, &mut PerfSampleData) -> i64,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
    arg4_type: ArgType,
}

enum RetType {
    Integer,
}

enum ArgType {
    ConstMapPtr,
    Anything,
    PtrToUninitMem,
    ConstSize,
}

// Rust中的__bpf_perf_event_output函数
fn __bpf_perf_event_output(regs: &PtRegs, map: &BpfMap, flags: u64, sd: &PerfSampleData) -> i64 {
    let array: &BpfArray = unsafe { &*(map as *const _ as *const BpfArray) }; // 使用unsafe进行类型转换
    let cpu = smp_processor_id();
    let mut index = flags & BPF_F_INDEX_MASK;
    
    if index == BPF_F_CURRENT_CPU {
        index = cpu as u64;
    }
    if index >= array.map.max_entries as u64 {
        return E2BIG;
    }

    let ee = match array.ptrs.get(index as usize).and_then(|e| e.as_ref()) {
        Some(e) => e,
        None => return ENOENT,
    };

    let event = unsafe { ee.event.as_ref() }; // 使用unsafe解引用NonNull指针
    if event.attr.type_ != PERF_TYPE_SOFTWARE || event.attr.config != PERF_COUNT_SW_BPF_OUTPUT {
        return EINVAL;
    }

    if event.oncpu != cpu {
        return EOPNOTSUPP;
    }

    perf_event_output(event, sd, regs)
}

// // 假设的常量定义
// const PERF_TYPE_SOFTWARE: u32 = 0x...;
// const PERF_COUNT_SW_BPF_OUTPUT: u64 = 0x...;

// 示例函数原型定义
static bpf_perf_event_read_value_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_perf_event_read_value, // 假设这个函数已经定义
    gpl_only: true,
    ret_type: RetType::Integer,
    arg1_type: ArgType::ConstMapPtr,
    arg2_type: ArgType::Anything,
    arg3_type: ArgType::PtrToUninitMem,
    arg4_type: ArgType::ConstSize,

    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};

// 注意：这里的代码示例包含了一些Rust不支持的操作，如直接的裸指针操作和类型转换，因此在实际应用中需要通过安全的封装来实现。
//655-660


// 定义与C语言兼容的结构体
#[repr(C)]
struct PerfSampleData {
    // 假设结构体成员
    // ...
}

#[repr(C)]
struct BpfTraceSampleData {
    sds: [PerfSampleData; 3],
}

// 使用静态变量表示每个 CPU 的变量
static BPF_TRACE_SDS: PerCpu<BpfTraceSampleData> = PerCpu::new();
static BPF_TRACE_NEST_LEVEL: PerCpu<i32> = PerCpu::new();

// 定义 PerCpu 结构体
struct PerCpu<T> {
    data: UnsafeCell<T>,
}

impl<T> PerCpu<T> {
    const fn new() -> Self {
        PerCpu {
            data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        }
    }

    fn get(&self) -> &T {
        unsafe { &*self.data.get() }
    }

    fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}
//661-709

fn bpf_perf_event_output(regs: NonNull<pt_regs>,map: NonNull<bpf_map>,flags:u64,data:NonNull<void>,size:u64)-> Result<(), i32>{
    let raw = perf_raw_record {
        frag: perf_frag_record {
            size,
            data: data.as_ptr(),
        },
    };

    // 禁用抢占和处理嵌套级别
    // Rust没有直接的抢占禁用机制，这里省略
    let nest_level = BPF_TRACE_NEST_LEVEL.with(|level| {
        *level.borrow_mut() += 1;
        *level.borrow()
    });

    let err = BPF_TRACE_SDS.with(|sds| {
        let mut sds = sds.borrow_mut();
        let sds = sds.get_or_insert_with(|| bpf_trace_sample_data { sds: Vec::new() });

        if nest_level as usize > sds.sds.len() {
            return Err(EBUSY);
        }

        if flags & !BPF_F_INDEX_MASK != 0 {
            return Err(EINVAL);
        }

        // 假设的初始化和保存数据函数
        let sd = perf_sample_data_init(0, 0);
        perf_sample_save_raw_data(&sd, &raw);

        // 假设的输出函数
        bindings::__bpf_perf_event_output(regs, map, flags, &sd)
    });

    // 减少嵌套级别
    BPF_TRACE_NEST_LEVEL.with(|level| *level.borrow_mut() -= 1);

    err
}

static  bpf_perf_event_output_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_perf_event_output, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_PTR_TO_CTX,
    arg2_type: ArgType::ARG_CONST_MAP_PTR,
    arg3_type: ArgType::ARG_ANYTHING,
    arg4_type: ArgType::ARG_PTR_TO_MEM | MEM_RDONLY,
    arg5_type: ArgType::ARG_CONST_SIZE_OR_ZERO,

    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//711-716


// 定义与C语言兼容的结构体
#[repr(C)]
struct PtRegs {
    // 假设结构体成员
    // ...
}

#[repr(C)]
struct BpfNestedPtRegs {
    regs: [PtRegs; 3],
}

#[repr(C)]
struct PerfSampleData {
    // 假设结构体成员
    // ...
}

#[repr(C)]
struct BpfTraceSampleData {
    sds: [PerfSampleData; 3],
}

// 使用静态变量表示每个 CPU 的变量
static BPF_EVENT_OUTPUT_NEST_LEVEL: PerCpu<i32> = PerCpu::new();
static BPF_PT_REGS: PerCpu<BpfNestedPtRegs> = PerCpu::new();
static BPF_MISC_SDS: PerCpu<BpfTraceSampleData> = PerCpu::new();

// 定义 PerCpu 结构体
struct PerCpu<T> {
    data: UnsafeCell<T>,
}

impl<T> PerCpu<T> {
    const fn new() -> Self {
        PerCpu {
            data: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        }
    }

    fn get(&self) -> &T {
        unsafe { &*self.data.get() }
    }

    fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}
//718-759
fn bpf_event_output(map:NonNull<bpf_map>, flags:u64 , meta:NonNull<c_void>, meta_size:u64 ,ctx:NonNull<c_void>, ctx_size:u64 , ctx_copy:bpf_ctx_copy_t )->u64{
    let frag= perf_raw_frag{
        copy: ctx_copy,
        size: ctx_size,
        data: ctx.as_ptr(),
    };
    struct PerfRawRecord {
        frag: PerfRawFrag,
    }
    
    // 假设frag已经被正确地定义和初始化
    let raw = PerfRawRecord {
        frag: PerfRawFrag {
            next: if ctx_size > 0 { Some(&frag as *const _) } else { None },
            size: meta_size,
            data: meta as *const u32, // 假设meta可以被转换为*const u8
        },
    };
    preempt_disable();
    let mut nest_level : i32= this_cpu_inc_return(bpf_event_output_nest_level);
    if WARN_ON_ONCE(nest_level as usize > ARRAY_SIZE ){
        // 错误处理，使用Result返回错误
        this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
        preempt_enable();
        return Err(-EBUSY);
    }

    let mut sd:NonNull<perf_sample_data> = this_cpu_ptr(&BPF_MISC_SDS.sds[nest_level - 1]);
    let mut regs:NonNull<pt_regs> = this_cpu_ptr(&BPF_PT_REGS.regs[nest_level - 1]);

    perf_fetch_caller_regs(regs);
    perf_sample_data_init(sd, 0, 0);
    perf_sample_save_raw_data(sd, &raw);

    let ret = __bpf_perf_event_output(regs, &(map.as_ptr()), flags, sd)?;

    // 正确的退出点
    this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
    preempt_enable();
    Ok(ret)
}
// 761-776
// BPF_CALL_0 宏的 Rust 实现
macro_rules! BPF_CALL_0 {
    ($func:ident) => {
        #[no_mangle]
        pub extern "C" fn $func() -> i64 {
            // 将 current 转换为 i64 类型并返回
            current as i64
        }
    };
}

// 使用 BPF_CALL_0 宏定义 bpf_get_current_task 函数
BPF_CALL_0!(bpf_get_current_task);

// 定义 bpf_func_proto 结构体
#[repr(C)]
pub struct bpf_func_proto {
    pub func: Option<extern "C" fn() -> i64>,
    pub gpl_only: bool,
    pub ret_type: i32,
}

// 定义 bpf_get_current_task_proto 常量
pub const bpf_get_current_task_proto: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_get_current_task),
    gpl_only: true,
    ret_type: 0, // 假设 RET_INTEGER 的值为 0

    arg1_type: 0,
    arg2_type: 0,
    arg3_type: 0,
    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};

// 使用 BPF_CALL_0 宏定义 bpf_get_current_task_btf 函数
BPF_CALL_0!(bpf_get_current_task_btf);
//777-829
static bpf_get_current_task_btf_proto:bpf_func_proto = bpf_func_proto {
    func: bpf_get_current_task_btf,
    gpl_only: true,
    ret_type: RET_PTR_TO_BTF_ID_TRUSTED,
    ret_btf_id: &btf_tracing_ids[BTF_TRACING_TYPE_TASK],

    arg1_type: 0,
    arg2_type: 0,
    arg3_type: 0,
    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
};
fn bpf_task_pt_regs(task : NonNull<task_struct>)-> u64{
    let ret = task_pt_regs(task) as u64;
    ret
}
bindings::BTF_ID_LIST!(bpf_task_pt_regs_ids);
bindings::BTF_ID!(struct, pt_regs);
static bpf_task_pt_regs_proto:bpf_func_proto  = bpf_func_proto {
    func: bpf_task_pt_regs,
    gpl_only: true,
    arg1_type	: ARG_PTR_TO_BTF_ID,
	arg1_btf_id	: &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	ret_type	: RET_PTR_TO_BTF_ID,
	ret_btf_id	: &bpf_task_pt_regs_ids[0],

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,

};

fn bpf_current_task_under_cgroup(map: NonNull<bpf_map>,idx: u32) -> i64 {
    unsafe{
        let array: NonNull<bpf_array> = container_of(map.as_ptr(), bpf_array, map.as_ptr());
        if unlikely(idx >= array.map.max_entries) {
            return -E2BIG;
        }
        let cgrp : cgroup = READ_ONCE(array.ptrs[idx]);
        if unlikely(!cgrp) {
            return -EAGAIN;
        }
        return task_under_cgroup_hierarchy(current, cgrp);
    }
}

static  bpf_current_task_under_cgroup_proto:bpf_func_proto  = bpf_func_proto{
	func           : bpf_current_task_under_cgroup,
	gpl_only       : false,
	ret_type       : RET_INTEGER,
	arg1_type      : ARG_CONST_MAP_PTR,
	arg2_type      : ARG_ANYTHING,

    arg3_type      : 0,
    arg4_type      : 0,
    arg5_type      : 0,
    arg1_btf_id    : 0,
    ret_btf_id     : 0,
};
struct send_signal_irq_work {
	irq_work:irq_work ,
    task: NonNull<task_struct>,
	sig:u32,
	typee: u32,
}
//830-842
bindings::DEFINE_PER_CPU!(send_signal_irq_work, send_signal_work);
fn do_bpf_send_signal(entry: *mut irq_work) 
{
    let work = container_of(entry, send_signal_work, irq_work);
    group_send_sig_info(work.sig, SEND_SIG_PRIV, work.task, work.typee);
    put_task_struct(work.task);
}
//843-883
fn bpf_send_signal_common(sig: u32, type_: PidType) -> i32 {
    let work: Option<&mut SendSignalIrqWork>;

    unsafe {
        if CURRENT.flags & (PF_KTHREAD | PF_EXITING) != 0 {
            return -1; // -EPERM
        }
        if !nmi_uaccess_okay() {
            return -1; // -EPERM
        }
        if is_global_init(&CURRENT) {
            return -1; // -EPERM
        }
    }

    if irqs_disabled() {
        if !valid_signal(sig) {
            return -22; // -EINVAL
        }

        work = Some(this_cpu_ptr(&SendSignalIrqWork {
            irq_work: IrqWork,
            task: TaskStruct::new(0),
            sig,
            type_: type_.clone(),
        }));

        if work.as_ref().unwrap().irq_work.is_busy() {
            return -16; // -EBUSY
        }

        unsafe {
            work.as_mut().unwrap().task = get_task_struct(&CURRENT);
            work.as_mut().unwrap().sig = sig;
            work.as_mut().unwrap().type_ = type_;
            work.as_ref().unwrap().irq_work.queue();
        }
        return 0;
    }

    group_send_sig_info(sig, SEND_SIG_PRIV, unsafe { &CURRENT }, type_)
}

//884-906
fn bpf_send_signal(sig : u32)-> i32{
    return bpf_send_signal_common(sig, PIDTYPE_TGID);
}
static  bpf_send_signal_proto:bpf_func_proto = bpf_func_proto{
	func		: bpf_send_signal,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_ANYTHING,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
fn bpf_send_signal_thread(sig : u32)-> i32{
    return bpf_send_signal_common(sig, PIDTYPE_PID);
}
static  bpf_send_signal_thread_proto:bpf_func_proto = bpf_func_proto{
	func		: bpf_send_signal_thread,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_ANYTHING,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
//908-936
// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(path: *mut Path, buf: *mut c_char, sz: u32) -> i64 {
            let mut copy = Path::default();
            let mut len: i64;
            let mut p: *mut c_char;

            if sz == 0 {
                return 0;
            }

            /*翻译：
             * path 指针已经被验证为可信和安全的,
             * 但是让我们再次检查它的有效性,以解决
             * 可能存在的验证器错误。
             */
            len = copy_from_kernel_nofault(&mut copy, path, std::mem::size_of::<Path>());
            if len < 0 {
                return len;
            }

            p = d_path(&copy, buf, sz);
            if p.is_null() {
                len = p as i64;
            } else {
                len = (buf as usize + sz as usize - p as usize) as i64;
                unsafe {
                    std::ptr::copy(p, buf, len as usize);
                }
            }

            len
        }
    };
}
//937-1010
// 定义BPF程序类型和附加类型的枚举
#[derive(PartialEq)]
enum BpfProgType {
    Tracing,
    Lsm,
    // 其他类型可以根据需要添加
}

enum BpfAttachType {
    TraceIter,
    // 其他附加类型可以根据需要添加
}

// 假设的外部变量和函数
// #[derive(HashSet)]
// struct BtfIdSet;
// 
// impl BtfIdSet {
//     fn contains(&self, id: u32) -> bool {
//         // 实现检查ID是否在集合中
//         false
//     }
// }
// 
// fn bpf_lsm_is_sleepable_hook(id: u32) -> bool {
//     // 检查给定的BPF LSM钩子是否可以睡眠
//     false
// }

// 假设的BPF程序结构体
struct BpfProg {
    prog_type: BpfProgType,
    expected_attach_type: BpfAttachType,
    aux: BpfProgAux,
}

// 假设的辅助结构体，包含附加BTF ID
struct BpfProgAux {
    attach_btf_id: u32,
}

// 允许列表的静态初始化
static BTF_ALLOWLIST_D_PATH: BtfIdSet = BtfIdSet::new();

fn bpf_d_path_allowed(prog: &BpfProg) -> bool {
    if prog.prog_type == BpfProgType::Tracing && prog.expected_attach_type == BpfAttachType::TraceIter {
        return true;
    }

    if prog.prog_type == BpfProgType::Lsm {
        return bpf_lsm_is_sleepable_hook(prog.aux.attach_btf_id);
    }

    BTF_ALLOWLIST_D_PATH.contains(prog.aux.attach_btf_id)
}

// 假设的BTF ID列表和函数原型
// struct BtfIdList;
// 
// struct BpfFuncProto {
//     func: fn(),
//     gpl_only: bool,
//     ret_type: ReturnType,
//     arg1_type: ArgType,
//     arg1_btf_id: u32,
//     arg2_type: ArgType,
//     arg3_type: ArgType,
//     allowed: fn(&BpfProg) -> bool,
// }

// BTF标志定义
const BTF_F_ALL: u64 = BTF_F_COMPACT | BTF_F_NONAME | BTF_F_PTR_RAW | BTF_F_ZERO;

// 假设的BTF和BTF指针结构体
// struct Btf;
// struct BtfPtr {
//     type_id: u32,
// }

fn bpf_btf_printf_prepare(ptr: &BtfPtr, btf_ptr_size: u32, flags: u64) -> Result<(), i32> {
    if flags & !BTF_F_ALL != 0 {
        return Err(-EINVAL);
    }

    if btf_ptr_size != std::mem::size_of::<BtfPtr>() as u32 {
        return Err(-EINVAL);
    }

    let btf = bpf_get_btf_vmlinux(); // 假设的函数，获取vmlinux的BTF
    if btf.is_err() {
        return Err(btf.err().unwrap());
    }

    let btf_id = if ptr.type_id > 0 { ptr.type_id } else { return Err(-EINVAL); };

    let t = btf_type_by_id(&btf, btf_id); // 假设的函数，通过ID获取BTF类型
    if t.is_none() {
        return Err(-ENOENT);
    }

    Ok(())
}
//1011-1025
// 假设的外部变量和函数
// struct BtfPtr {
//     ptr: *const c_void,
//     type_id: u32,
// }
// 
// struct Btf;
// 
// fn bpf_btf_printf_prepare(ptr: &BtfPtr, btf_ptr_size: u32, flags: u64) -> Result<(&Btf, u32), i32> {
//     // 准备打印BTF信息的函数，返回BTF引用和BTF ID或错误码
//     Err(-1)
// }
// 
// fn btf_type_snprintf_show(btf: &Btf, btf_id: u32, ptr: *const c_void, str: &mut [u8], str_size: usize, flags: u64) -> i32 {
//     // 将BTF类型信息格式化为字符串的函数
//     0
// }



// Rust版本的bpf_snprintf_btf函数
unsafe fn bpf_snprintf_btf(str: *mut c_char, str_size: u32, ptr: *const BtfPtr, btf_ptr_size: u32, flags: u64) -> i32 {
    // 尝试准备打印BTF信息
    match bpf_btf_printf_prepare(&*ptr, btf_ptr_size, flags) {
        Ok((btf, btf_id)) => {
            // 如果准备成功，尝试将BTF类型信息格式化为字符串
            let str_slice = std::slice::from_raw_parts_mut(str as *mut u8, str_size as usize);
            btf_type_snprintf_show(btf, btf_id, (*ptr).ptr, str_slice, str_size as usize, flags)
        },
        Err(e) => e, // 如果准备失败，返回错误码
    }
}
//1027-1036
// 定义返回类型和参数类型的枚举
enum RetType {
    Integer,
}

enum ArgType {
    PtrToMem,
    ConstSize,
    PtrToMemReadonly,
    Anything,
}

// 定义函数指针类型
type BpfFunc = fn(*mut u8, usize, *const u8, usize, u64) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
    arg4_type: ArgType,
    arg5_type: ArgType,
}

// 定义bpf_snprintf_btf函数
fn bpf_snprintf_btf(buf: *mut u8, buf_size: usize, fmt: *const u8, fmt_size: usize, arg: u64) -> i32 {
    // 函数实现
    0
}
//1037-1043
// 假设的外部类型和常量
// use std::os::raw::{c_void, c_ulong};

// BPF调用宏的Rust版本，用于获取函数的IP地址（用于追踪）
// 这个函数是一个内联函数，通常由验证器内联
unsafe fn bpf_get_func_ip_tracing(ctx: *const c_void) -> u64 {
    // 将传入的上下文（ctx）转换为一个指向u64的指针
    // 然后向后移动2个单位（因为ctx是一个指向栈顶的指针，我们需要获取调用函数的地址，通常位于栈顶以下两个位置）
    // 最后，通过解引用获取该位置的值，即函数的IP地址
    *((ctx as *const u64).offset(-2))
}
//1044-1049
// 示例：创建一个BpfFuncProto实例
static  bpf_get_func_ip_proto_tracing:bpf_func_proto = bpf_func_proto {
    // 假设的外部函数，这里用一个示例函数来代替
    // 实际使用时，应该替换为正确的函数指针
    func: bpf_get_func_ip_tracing, // 假设的函数指针
    gpl_only: true,
    ret_type: RetType::Integer,
    arg1_type: ArgType::PtrToCtx,

    arg2_type: 0,
    arg3_type: 0,
    arg4_type: 0,
    arg5_type: 0,
    arg1_btf_id: 0,
    ret_btf_id: 0,
};
//1052-1062
extern "C"
{
    fn get_kernel_nofault(instr: u32, fentry_ip: *mut u32) -> u32;
    fn is_endbr(instr: u32) -> u32;
    static ENDBR_INSN_SIZE: u32;
}

pub fn get_entry_ip(fentry_ip: u64) -> u64 {
    let instr: u32;
    if unsafe { get_kernel_nofault(instr, fentry_ip as *mut u32) } != 0 {
        return fentry_ip;
    }
    if unsafe { is_endbr(instr) } != 0 {
        return fentry_ip - unsafe { ENDBR_INSN_SIZE } as u64;
    }
    return fentry_ip;
}
//1067-1166
fn bpf_get_func_ip_kprobe(regs:Nonull<pt_regs>)-> i32 {
    unsafe{
        if cfg!(feature = "CONFIG_UPROBES") {
            let mut run_ctx : NonNull<bpf_trace_run_ctx>=container_of(current.bpf_ctx, bpf_trace_run_ctx, run_ctx);
            if (run_ctx.is_uprobe)!=0 {
                return *((current.utask.vaddr as NonNull<uprobe_dispatch_data>).as_ptr()).bp_addr;
            }
        } 
        else {
            let mut kp : NonNull<kprobe> = kprobe_running();
            if (!kp || !(kp.flags & KPROBE_FLAG_ON_FUNC_ENTRY)) {
		        return 0;
            }
            return get_entry_ip(kp.addr as uintptr_t);
        }  
    }
}
static  bpf_get_func_ip_proto_kprobe : bpf_func_proto = bpf_func_proto{
	func		: bpf_get_func_ip_kprobe,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
unsafe fn bpf_get_func_ip_kprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_kprobe_multi_cookie(current.bpf_ctx);
}
static  bpf_get_attach_cookie_proto_kmulti : bpf_func_proto = bpf_func_proto{
	func		: bpf_get_attach_cookie_kprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
unsafe fn bpf_get_func_ip_uprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_uprobe_multi_entry_ip(current.bpf_ctx);
}
static  bpf_get_func_ip_proto_uprobe_multi : bpf_func_proto = bpf_func_proto{
	func		: bpf_get_func_ip_uprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
unsafe fn bpf_get_attach_cookie_uprobe_multi(regs : NonNull<pt_regs>)->i32{
    return bpf_uprobe_multi_cookie(current.bpf_ctx);
}
static  bpf_get_attach_cookie_proto_umulti : bpf_func_proto = bpf_func_proto{
	func		: bpf_get_attach_cookie_uprobe_multi,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
fn bpf_get_attach_cookie_trace(ctx : NonNull<c_void>)-> i32{
    unsafe{
        let run_ctx : NonNull<bpf_trace_run_ctx> = container_of(current.bpf_ctx,  bpf_trace_run_ctx, run_ctx);
        return *(run_ctx.as_ptr()).cookie;
    }
}
static  bpf_get_attach_cookie_proto_trace:bpf_func_proto = bpf_func_proto{
	func		: bpf_get_attach_cookie_trace,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
fn bpf_get_attach_cookie_pe(ctx : NonNull<bpf_perf_event_data_kern>){
    unsafe{
        return *(ctx.as_ptr()).event.bpf_cookie;
    }
}
static  bpf_get_attach_cookie_proto_pe:bpf_func_proto = bpf_func_proto{
	func		: bpf_get_attach_cookie_pe,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
//1168-1175
// BPF_CALL_1 宏的 Rust 实现
macro_rules! BPF_CALL_1 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(ctx: *mut c_void) -> u64 {
            // 获取当前线程的 bpf_ctx
            let bpf_ctx = current().bpf_ctx;
            
            // 使用 container_of 宏从 bpf_ctx 中获取 BpfTraceRunCtx 结构体
            let run_ctx = container_of(bpf_ctx, BpfTraceRunCtx, run_ctx);
            
            // 返回 BpfTraceRunCtx 结构体中的 bpf_cookie 字段
            run_ctx.bpf_cookie
        }
    };
}
//1176-1228
static  bpf_get_attach_cookie_proto_tracing:bpf_func_proto = bpf_func_proto{
	func		: bpf_get_attach_cookie_tracing,
	gpl_only	: false,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,

    arg2_type	: 0,
    arg3_type	: 0,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
fn bpf_get_branch_snapshot(buf:NonNull<c_void>,size:u32,flags:u64)->i32{
    unsafe{
        if(cfg!(feature != "CONFIG_X86")){
            return -ENOENT;
        }
        else {
            let br_entry_size : u32= size_of::<perf_branch_entry>();
            let mut entry_cnt : u32 = size/br_entry_size;
            entry_cnt = static_call(perf_snapshot_branch_stack)(buf.as_ptr(), entry_cnt);
            if unlikely(flags){
                return -EINVAL;
            }
            if !entry_cnt{
                return -ENOENT;
            }
            return entry_cnt * br_entry_size ;
        }
    }
}
static  bpf_get_branch_snapshot_proto:bpf_func_proto = bpf_func_proto{
	func		: bpf_get_branch_snapshot,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_UNINIT_MEM,
	arg2_type	: ARG_CONST_SIZE_OR_ZERO,

    arg3_type	: ARG_ANYTHING,
    arg4_type	: 0,
    arg5_type	: 0,
    arg1_btf_id	: 0,
    ret_btf_id	: 0,
};
fn get_func_arg(ctx:NonNull<c_void>,n:u32,value:NonNull<u64>)->i64{
    unsafe{
        // 将ctx从NonNull<c_void>转换为NonNull<u64>
        let ctx_u64 = ctx.cast::<u64>();
        // 使用offset方法访问前一个位置的指针，并解引用获取值
        let mut nr_args = *ctx_u64.as_ptr().offset(-1);
        // 根据需要使用nr_args
        if n as u64 >= nr_args{
            return -EINVAL;
        }
        *(value.as_ptr())= *ctx_u64.as_ptr().offset(n as isize);
        return 0;
    }
}
static  bpf_get_func_arg_proto:bpf_func_proto = bpf_func_proto{
	func		: get_func_arg,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_ANYTHING,
	arg3_type	: ARG_PTR_TO_LONG,

    arg4_type    : 0,
    arg5_type    : 0,
    arg1_btf_id  : 0,
    ret_btf_id   : 0,
    gpl_only     : false,
};
//1230-1237


fn get_func_ret(ctx: NonNull<c_void>, value: NonNull<u64>) -> i32 {
    unsafe {
        // 将 ctx 转换为 *mut u64 指针，以便进行算术操作
        let ctx_ptr = ctx.as_ptr() as *mut u64;

        // 获取 nr_args 的值。由于 ctx 指向的是 u64 数组，我们可以通过偏移 -1 来访问数组前一个元素
        let nr_args = *ctx_ptr.offset(-1);

        // 根据 nr_args 的值，从 ctx 指向的数组中获取相应的值，并将其写入 value 指向的位置
        *value.as_ptr() = *ctx_ptr.offset(nr_args as isize);
    }

    0 // 按照原始宏的定义，这里返回 0
}
//1238-1502
// 定义返回类型和参数类型的枚举
enum RetType {
    Integer,
}

enum ArgType {
    PtrToCtx,
    PtrToLong,
}

// 定义函数指针类型
type BpfFunc = fn(*const u8, *const i64) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
}

// 定义get_func_ret函数
fn get_func_ret(ctx: *const u8, value: *const i64) -> i32 {
    unsafe {
        // 假设从上下文指针获取整数值
        let ctx_value = *(ctx as *const i32); 
        // 获取传入的长整数值
        let value = *value; 
        // 返回上下文值与传入值的和
        (ctx_value + value) as i32
    }
}
// 定义get_func_arg_cnt函数
fn get_func_arg_cnt(ctx: *mut std::ffi::c_void) -> u64 {
    unsafe {
        // 将ctx转换为指向u64的指针，并偏移-1
        *((ctx as *mut u64).offset(-1))
    }
}
// 定义返回类型和参数类型的枚举
enum RetType {
    Integer,
}

enum ArgType {
    PtrToCtx,
}

// 定义函数指针类型
type BpfFunc = fn(*mut std::ffi::c_void) -> u64;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    ret_type: RetType,
    arg1_type: ArgType,
}

// 定义get_func_arg_cnt函数
fn get_func_arg_cnt(ctx: *mut std::ffi::c_void) -> u64 {
    unsafe {
        // 将ctx转换为指向u64的指针，并偏移-1
        *((ctx as *mut u64).offset(-1))
    }
}

// 实例化BpfFuncProto
static BPF_GET_FUNC_ARG_CNT_PROTO: bpf_func_proto = bpf_func_proto {
    func: get_func_arg_cnt,
    ret_type: RetType::Integer,
    arg1_type: ArgType::PtrToCtx,
    arg2_type: 0,
    arg3_type: 0,
    arg4_type: 0,
    arg5_type: 0,
    gpl_only: false,
    ret_btf_id: 0,
    arg1_btf_id: 0,
};
#[cfg(CONFIG_KEYS)]
mod bpf_kfunc {


    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }

    // 定义用于表示密钥查找的标志
    pub const KEY_LOOKUP_CREATE: u64 = 0x1;
    pub const KEY_LOOKUP_PARTIAL: u64 = 0x2;
    pub const KEY_LOOKUP_ALL: u64 = KEY_LOOKUP_CREATE | KEY_LOOKUP_PARTIAL;
    pub const KEY_DEFER_PERM_CHECK: u64 = 0x4;

    extern "C" {
        fn lookup_user_key(serial: u32, flags: u64, perm_check: u64) -> *mut c_void;
        fn key_ref_to_ptr(key_ref: *mut c_void) -> *mut c_void;
        fn key_put(key: *mut c_void);
        fn kmalloc(size: usize, flags: u32) -> *mut c_void;
        fn IS_ERR(ptr: *mut c_void) -> bool;
        fn GFP_KERNEL() -> u32;
    }

    // 查找用户密钥的函数
    pub unsafe fn bpf_lookup_user_key(serial: u32, flags: u64) -> *mut BpfKey {
        if flags & !KEY_LOOKUP_ALL != 0 {
            return ptr::null_mut();
        }

        let key_ref = lookup_user_key(serial, flags, KEY_DEFER_PERM_CHECK);
        if IS_ERR(key_ref) {
            return ptr::null_mut();
        }

        let bkey = kmalloc(std::mem::size_of::<BpfKey>(), GFP_KERNEL());
        if bkey.is_null() {
            key_put(key_ref_to_ptr(key_ref));
            return ptr::null_mut();
        }

        let bkey_ptr = bkey as *mut BpfKey;
        (*bkey_ptr).key = key_ref_to_ptr(key_ref);
        (*bkey_ptr).has_ref = true;

        bkey_ptr
    }
}
#[cfg(CONFIG_KEYS)]
mod bpf_kfunc {


    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }

    extern "C" {
        fn system_keyring_id_check(id: u64) -> i32;
        fn kmalloc(size: usize, flags: u32) -> *mut c_void;
        fn GFP_ATOMIC() -> u32;
    }

    // 查找系统密钥的函数
    pub unsafe fn bpf_lookup_system_key(id: u64) -> *mut BpfKey {
        if system_keyring_id_check(id) < 0 {
            return ptr::null_mut();
        }

        let bkey = kmalloc(std::mem::size_of::<BpfKey>(), GFP_ATOMIC());
        if bkey.is_null() {
            return ptr::null_mut();
        }

        let bkey_ptr = bkey as *mut BpfKey;
        (*bkey_ptr).key = id as *mut c_void;
        (*bkey_ptr).has_ref = false;

        bkey_ptr
    }
}
#[cfg(CONFIG_KEYS)]
mod bpf_kfunc {


    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }

    extern "C" {
        fn key_put(key: *mut c_void);
        fn kfree(ptr: *mut c_void);
    }

    // 减少密钥引用计数并释放bpf_key结构体的函数
    pub unsafe fn bpf_key_put(bkey: *mut BpfKey) {
        if (*bkey).has_ref {
            key_put((*bkey).key);
        }
        kfree(bkey as *mut c_void);
    }
}
#[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
mod bpf_kfunc {


    // 定义用于表示动态指针的结构体
    pub struct BpfDynptrKern {
        // 具体内容省略
    }

    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }

    extern "C" {
        fn key_validate(key: *mut c_void) -> i32;
        fn verify_pkcs7_signature(data: *const c_void, data_len: u32,
                                  sig: *const c_void, sig_len: u32,
                                  key: *mut c_void, usage: u32,
                                  p1: *mut c_void, p2: *mut c_void) -> i32;
        fn __bpf_dynptr_size(dynptr: *mut BpfDynptrKern) -> u32;
        fn __bpf_dynptr_data(dynptr: *mut BpfDynptrKern, size: u32) -> *const c_void;
        const VERIFYING_UNSPECIFIED_SIGNATURE: u32;
    }

    // 验证PKCS#7签名的函数
    pub unsafe fn bpf_verify_pkcs7_signature(data_ptr: *mut BpfDynptrKern,
                                             sig_ptr: *mut BpfDynptrKern,
                                             trusted_keyring: *mut BpfKey) -> i32 {
        if (*trusted_keyring).has_ref {
            let ret = key_validate((*trusted_keyring).key);
            if ret < 0 {
                return ret;
            }
        }

        let data_len = __bpf_dynptr_size(data_ptr);
        let data = __bpf_dynptr_data(data_ptr, data_len);
        let sig_len = __bpf_dynptr_size(sig_ptr);
        let sig = __bpf_dynptr_data(sig_ptr, sig_len);

        verify_pkcs7_signature(data, data_len, sig, sig_len,
                               (*trusted_keyring).key,
                               VERIFYING_UNSPECIFIED_SIGNATURE, ptr::null_mut(), ptr::null_mut())
    }
}
// 使用常量定义函数标志
const KF_ACQUIRE: u32 = 1 << 0;
const KF_RET_NULL: u32 = 1 << 1;
const KF_SLEEPABLE: u32 = 1 << 2;
const KF_RELEASE: u32 = 1 << 3;

// 定义用于表示 BTF 函数 ID 和标志的结构体
struct BtfIdFlags {
    func: fn(),
    flags: u32,
}

// 定义用于表示 BTF 函数集合的结构体
struct BtfSet {
    ids: &'static [BtfIdFlags],
}

// 定义 BTF 函数集合
static KEY_SIG_KFUNC_SET: BtfSet = BtfSet {
    ids: &[
        BtfIdFlags { func: bpf_lookup_user_key as fn(), flags: KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE },
        BtfIdFlags { func: bpf_lookup_system_key as fn(), flags: KF_ACQUIRE | KF_RET_NULL },
        BtfIdFlags { func: bpf_key_put as fn(), flags: KF_RELEASE },
        #[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
        BtfIdFlags { func: bpf_verify_pkcs7_signature as fn(), flags: KF_SLEEPABLE },
    ],
};

// BTF 函数定义
extern "C" {
    fn bpf_lookup_user_key();
    fn bpf_lookup_system_key();
    fn bpf_key_put();
    #[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
    fn bpf_verify_pkcs7_signature();
}
#[cfg(CONFIG_KEYS)]
mod bpf_kfunc {


    // 定义用于表示 BTF 函数 ID 集合的结构体
    #[repr(C)]
    struct BtfKfuncIdSet {
        owner: *const u8,
        set: *const BtfSet,
    }

    // 定义用于表示 BTF 函数集合的结构体
    #[repr(C)]
    struct BtfSet {
        ids: &'static [BtfIdFlags],
    }

    // 定义用于表示函数标志的结构体
    #[repr(C)]
    struct BtfIdFlags {
        func: fn(),
        flags: u32,
    }

    // 使用常量定义函数标志
    const KF_ACQUIRE: u32 = 1 << 0;
    const KF_RET_NULL: u32 = 1 << 1;
    const KF_SLEEPABLE: u32 = 1 << 2;
    const KF_RELEASE: u32 = 1 << 3;

    // BTF 函数集合
    static KEY_SIG_KFUNC_SET: BtfSet = BtfSet {
        ids: &[
            BtfIdFlags { func: bpf_lookup_user_key as fn(), flags: KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE },
            BtfIdFlags { func: bpf_lookup_system_key as fn(), flags: KF_ACQUIRE | KF_RET_NULL },
            BtfIdFlags { func: bpf_key_put as fn(), flags: KF_RELEASE },
            #[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
            BtfIdFlags { func: bpf_verify_pkcs7_signature as fn(), flags: KF_SLEEPABLE },
        ],
    };

    // BTF 函数 ID 集合
    static BPF_KEY_SIG_KFUNC_SET: BtfKfuncIdSet = BtfKfuncIdSet {
        owner: THIS_MODULE,
        set: &KEY_SIG_KFUNC_SET,
    };

    extern "C" {
        fn register_btf_kfunc_id_set(prog_type: u32, id_set: *const BtfKfuncIdSet) -> i32;
        fn bpf_lookup_user_key();
        fn bpf_lookup_system_key();
        fn bpf_key_put();
        #[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
        fn bpf_verify_pkcs7_signature();
    }

    // 初始化函数
    fn bpf_key_sig_kfuncs_init() -> i32 {
        unsafe {
            register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &BPF_KEY_SIG_KFUNC_SET)
        }
    }

    // 使用内核模块初始化宏
    module_init!(bpf_key_sig_kfuncs_init);
}// 定义文件和动态指针结构体
#[repr(C)]
pub struct File;

#[repr(C)]
pub struct BpfDynptrKern;

// 常量定义
const XATTR_USER_PREFIX: &str = "user.";
const XATTR_USER_PREFIX_LEN: usize = XATTR_USER_PREFIX.len();
const EPERM: i32 = -1;
const EINVAL: i32 = -22;
const MAY_READ: u32 = 0x4;

// 外部函数声明
extern "C" {
    fn __bpf_dynptr_size(value_ptr: *mut BpfDynptrKern) -> u32;
    fn __bpf_dynptr_data_rw(value_ptr: *mut BpfDynptrKern, size: u32) -> *mut u8;
    fn file_dentry(file: *mut File) -> *mut Dentry;
    fn inode_permission(idmap: *const c_void, inode: *mut Inode, mask: u32) -> i32;
    fn __vfs_getxattr(dentry: *mut Dentry, inode: *mut Inode, name: *const i8, value: *mut u8, size: u32) -> i32;
}

// 定义文件目录和索引节点结构体
#[repr(C)]
struct Dentry {
    d_inode: *mut Inode,
}

#[repr(C)]
struct Inode;

// 函数实现
pub unsafe fn bpf_get_file_xattr(file: *mut File, name__str: *const i8, value_ptr: *mut BpfDynptrKern) -> i32 {
    if std::ffi::CStr::from_ptr(name__str).to_str().unwrap_or("")[..XATTR_USER_PREFIX_LEN] != XATTR_USER_PREFIX {
        return EPERM;
    }

    let value_len = __bpf_dynptr_size(value_ptr);
    let value = __bpf_dynptr_data_rw(value_ptr, value_len);
    if value.is_null() {
        return EINVAL;
    }

    let dentry = file_dentry(file);
    let ret = inode_permission(ptr::null(), (*dentry).d_inode, MAY_READ);
    if ret != 0 {
        return ret;
    }
    __vfs_getxattr(dentry, (*dentry).d_inode, name__str, value, value_len)
}
// 使用常量定义函数标志
const KF_SLEEPABLE: u32 = 1 << 0;
const KF_TRUSTED_ARGS: u32 = 1 << 1;
const EACCES: i32 = 13;
const BPF_PROG_TYPE_LSM: u32 = 15;

// 定义用于表示函数标志的结构体
struct BtfIdFlags {
    func: fn(),
    flags: u32,
}

// 定义用于表示 BTF 函数集合的结构体
struct BtfSet {
    ids: &'static [BtfIdFlags],
}

// BTF 函数集合
static FS_KFUNC_SET_IDS: BtfSet = BtfSet {
    ids: &[
        BtfIdFlags { func: bpf_get_file_xattr as fn(), flags: KF_SLEEPABLE | KF_TRUSTED_ARGS },
    ],
};

// BPF 程序结构体
#[repr(C)]
struct BpfProg {
    type_: u32,
}

// 外部函数声明
extern "C" {
    fn btf_id_set8_contains(set: *const BtfSet, kfunc_id: u32) -> bool;
    fn bpf_get_file_xattr();
}

// 过滤函数实现
unsafe fn bpf_get_file_xattr_filter(prog: *const BpfProg, kfunc_id: u32) -> i32 {
    if !btf_id_set8_contains(&FS_KFUNC_SET_IDS, kfunc_id) {
        return 0;
    }

    // 只有从 LSM hooks 附加时才允许，以避免递归
    if (*prog).type_ != BPF_PROG_TYPE_LSM {
        return -EACCES;
    }
    0
}
//1504-1635
// bpf_tracing_func_proto 函数的 Rust 实现
fn bpf_tracing_func_proto(func_id: bpf_func_id, prog: &bpf_prog) -> Option<&'static bpf_func_proto> {
    match func_id {
        bpf_func_id::BPF_FUNC_map_lookup_elem => Some(&BPF_MAP_LOOKUP_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_update_elem => Some(&BPF_MAP_UPDATE_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_delete_elem => Some(&BPF_MAP_DELETE_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_push_elem => Some(&BPF_MAP_PUSH_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_pop_elem => Some(&BPF_MAP_POP_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_peek_elem => Some(&BPF_MAP_PEEK_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_map_lookup_percpu_elem => Some(&BPF_MAP_LOOKUP_PERCPU_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_ktime_get_ns => Some(&BPF_KTIME_GET_NS_PROTO),
        bpf_func_id::BPF_FUNC_ktime_get_boot_ns => Some(&BPF_KTIME_GET_BOOT_NS_PROTO),
        bpf_func_id::BPF_FUNC_tail_call => Some(&BPF_TAIL_CALL_PROTO),
        bpf_func_id::BPF_FUNC_get_current_pid_tgid => Some(&BPF_GET_CURRENT_PID_TGID_PROTO),
        bpf_func_id::BPF_FUNC_get_current_task => Some(&BPF_GET_CURRENT_TASK_PROTO),
        bpf_func_id::BPF_FUNC_get_current_task_btf => Some(&BPF_GET_CURRENT_TASK_BTF_PROTO),
        bpf_func_id::BPF_FUNC_task_pt_regs => Some(&BPF_TASK_PT_REGS_PROTO),
        bpf_func_id::BPF_FUNC_get_current_uid_gid => Some(&BPF_GET_CURRENT_UID_GID_PROTO),
        bpf_func_id::BPF_FUNC_get_current_comm => Some(&BPF_GET_CURRENT_COMM_PROTO),
        bpf_func_id::BPF_FUNC_trace_printk => bpf_get_trace_printk_proto(),
        bpf_func_id::BPF_FUNC_get_smp_processor_id => Some(&BPF_GET_SMP_PROCESSOR_ID_PROTO),
        bpf_func_id::BPF_FUNC_get_numa_node_id => Some(&BPF_GET_NUMA_NODE_ID_PROTO),
        bpf_func_id::BPF_FUNC_perf_event_read => Some(&BPF_PERF_EVENT_READ_PROTO),
        bpf_func_id::BPF_FUNC_current_task_under_cgroup => Some(&BPF_CURRENT_TASK_UNDER_CGROUP_PROTO),
        bpf_func_id::BPF_FUNC_get_prandom_u32 => Some(&BPF_GET_PRANDOM_U32_PROTO),
        bpf_func_id::BPF_FUNC_probe_write_user => {
            if security_locked_down(LOCKDOWN_BPF_WRITE_USER) < 0 {
                None
            } else {
                bpf_get_probe_write_proto()
            }
        }
        bpf_func_id::BPF_FUNC_probe_read_user => Some(&BPF_PROBE_READ_USER_PROTO),
        bpf_func_id::BPF_FUNC_probe_read_kernel => {
            if security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 {
                None
            } else {
                Some(&BPF_PROBE_READ_KERNEL_PROTO)
            }
        }
        bpf_func_id::BPF_FUNC_probe_read_user_str => Some(&BPF_PROBE_READ_USER_STR_PROTO),
        bpf_func_id::BPF_FUNC_probe_read_kernel_str => {
            if security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 {
                None
            } else {
                Some(&BPF_PROBE_READ_KERNEL_STR_PROTO)
            }
        }
        #[cfg(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE)]
        bpf_func_id::BPF_FUNC_probe_read => {
            if security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 {
                None
            } else {
                Some(&BPF_PROBE_READ_COMPAT_PROTO)
            }
        }
        #[cfg(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE)]
        bpf_func_id::BPF_FUNC_probe_read_str => {
            if security_locked_down(LOCKDOWN_BPF_READ_KERNEL) < 0 {
                None
            } else {
                Some(&BPF_PROBE_READ_COMPAT_STR_PROTO)
            }
        }
        #[cfg(CONFIG_CGROUPS)]
        bpf_func_id::BPF_FUNC_cgrp_storage_get => Some(&BPF_CGRP_STORAGE_GET_PROTO),
        #[cfg(CONFIG_CGROUPS)]
        bpf_func_id::BPF_FUNC_cgrp_storage_delete => Some(&BPF_CGRP_STORAGE_DELETE_PROTO),
        bpf_func_id::BPF_FUNC_send_signal => Some(&BPF_SEND_SIGNAL_PROTO),
        bpf_func_id::BPF_FUNC_send_signal_thread => Some(&BPF_SEND_SIGNAL_THREAD_PROTO),
        bpf_func_id::BPF_FUNC_perf_event_read_value => Some(&BPF_PERF_EVENT_READ_VALUE_PROTO),
        bpf_func_id::BPF_FUNC_get_ns_current_pid_tgid => Some(&BPF_GET_NS_CURRENT_PID_TGID_PROTO),
        bpf_func_id::BPF_FUNC_ringbuf_output => Some(&BPF_RINGBUF_OUTPUT_PROTO),
        bpf_func_id::BPF_FUNC_ringbuf_reserve => Some(&BPF_RINGBUF_RESERVE_PROTO),
        bpf_func_id::BPF_FUNC_ringbuf_submit => Some(&BPF_RINGBUF_SUBMIT_PROTO),
        bpf_func_id::BPF_FUNC_ringbuf_discard => Some(&BPF_RINGBUF_DISCARD_PROTO),
        bpf_func_id::BPF_FUNC_ringbuf_query => Some(&BPF_RINGBUF_QUERY_PROTO),
        bpf_func_id::BPF_FUNC_jiffies64 => Some(&BPF_JIFFIES64_PROTO),
        bpf_func_id::BPF_FUNC_get_task_stack => Some(&BPF_GET_TASK_STACK_PROTO),
        bpf_func_id::BPF_FUNC_copy_from_user => Some(&BPF_COPY_FROM_USER_PROTO),
        bpf_func_id::BPF_FUNC_copy_from_user_task => Some(&BPF_COPY_FROM_USER_TASK_PROTO),
        bpf_func_id::BPF_FUNC_snprintf_btf => Some(&BPF_SNPRINTF_BTF_PROTO),
        bpf_func_id::BPF_FUNC_per_cpu_ptr => Some(&BPF_PER_CPU_PTR_PROTO),
        bpf_func_id::BPF_FUNC_this_cpu_ptr => Some(&BPF_THIS_CPU_PTR_PROTO),
        bpf_func_id::BPF_FUNC_task_storage_get => {
            if bpf_prog_check_recur(prog) {
                Some(&BPF_TASK_STORAGE_GET_RECUR_PROTO)
            } else {
                Some(&BPF_TASK_STORAGE_GET_PROTO)
            }
        }
        bpf_func_id::BPF_FUNC_task_storage_delete => {
            if bpf_prog_check_recur(prog) {
                Some(&BPF_TASK_STORAGE_DELETE_RECUR_PROTO)
            } else {
                Some(&BPF_TASK_STORAGE_DELETE_PROTO)
            }
        }
        bpf_func_id::BPF_FUNC_for_each_map_elem => Some(&BPF_FOR_EACH_MAP_ELEM_PROTO),
        bpf_func_id::BPF_FUNC_snprintf => Some(&BPF_SNPRINTF_PROTO),
        bpf_func_id::BPF_FUNC_get_func_ip => Some(&BPF_GET_FUNC_IP_PROTO_TRACING),
        bpf_func_id::BPF_FUNC_get_branch_snapshot => Some(&BPF_GET_BRANCH_SNAPSHOT_PROTO),
        bpf_func_id::BPF_FUNC_find_vma => Some(&BPF_FIND_VMA_PROTO),
        bpf_func_id::BPF_FUNC_trace_vprintk => bindings::bpf_get_trace_vprintk_proto(),
        _ => bpf_base_func_proto(func_id),
    }
}
//1636-1666
// kprobe_prog_func_proto 函数的 Rust 实现
fn kprobe_prog_func_proto(func_id: bpf_func_id, prog: &bpf_prog) -> Option<&'static bpf_func_proto> {
    match func_id {
        bpf_func_id::BPF_FUNC_perf_event_output => Some(&BPF_PERF_EVENT_OUTPUT_PROTO),
        bpf_func_id::BPF_FUNC_get_stackid => Some(&BPF_GET_STACKID_PROTO),
        bpf_func_id::BPF_FUNC_get_stack => Some(&BPF_GET_STACK_PROTO),
        #[cfg(CONFIG_BPF_KPROBE_OVERRIDE)]
        bpf_func_id::BPF_FUNC_override_return => Some(&BPF_OVERRIDE_RETURN_PROTO),
        bpf_func_id::BPF_FUNC_get_func_ip => match prog.expected_attach_type {
            bpf_probe_attach_type::BPF_TRACE_KPROBE_MULTI => Some(&BPF_GET_FUNC_IP_PROTO_KPROBE_MULTI),
            bpf_probe_attach_type::BPF_TRACE_UPROBE_MULTI => Some(&BPF_GET_FUNC_IP_PROTO_UPROBE_MULTI),
            _ => Some(&BPF_GET_FUNC_IP_PROTO_KPROBE),
        },
        bpf_func_id::BPF_FUNC_get_attach_cookie => match prog.expected_attach_type {
            bpf_probe_attach_type::BPF_TRACE_KPROBE_MULTI => Some(&BPF_GET_ATTACH_COOKIE_PROTO_KMULTI),
            bpf_probe_attach_type::BPF_TRACE_UPROBE_MULTI => Some(&BPF_GET_ATTACH_COOKIE_PROTO_UMULTI),
            _ => Some(&BPF_GET_ATTACH_COOKIE_PROTO_TRACE),
        },
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}
//1667-1687
// kprobe_prog_is_valid_access 函数的 Rust 实现
// bpf+kprobe 程序可以访问 'struct pt_regs' 的字段
fn kprobe_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 检查偏移量是否在 'struct pt_regs' 的范围内
    if off < 0 || off >= std::mem::size_of::<pt_regs>() as i32 {
        return false;
    }
    // 检查访问类型是否为读
    if access_type != bpf_access_type::BPF_READ {
        return false;
    }
    // 检查偏移量是否与访问大小对齐
    if off % size != 0 {
        return false;
    }
    // 断言: 对于 32 位系统,确保最后 8 字节访问 (BPF_DW) 到最后 4 字节成员是不允许的
    if off as usize + size as usize > std::mem::size_of::<pt_regs>() {
        return false;
    }

    true
}
//1688-1695
// 两个模块的 Rust 实现
// 定义 kprobe 验证器操作
const KPROBE_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    // 获取函数原型的函数指针
    get_func_proto: Some(kprobe_prog_func_proto),
    // 检查访问是否有效的函数指针
    is_valid_access: Some(kprobe_prog_is_valid_access),
};

const KPROBE_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
};
//1696-1707
// Rust版本的bpf_perf_event_output_tp函数
// 使用`unsafe`因为我们将要进行裸指针操作和调用C函数
unsafe fn bpf_perf_event_output_tp(tp_buff: *mut c_void, map: *mut BpfMap, flags: c_ulonglong, data: *mut c_void, size: c_ulonglong) -> i32 {
    // 将`tp_buff`转换为`**PtRegs`类型的裸指针，以便获取`struct pt_regs`的指针
    let regs = *(tp_buff as *mut *mut PtRegs);

    /*
     * `r1`指向perf tracepoint缓冲区，其中前8字节对bpf程序隐藏，
     * 并包含指向`struct pt_regs`的指针。从那里获取它，
     * 并内联调用相同的`bpf_perf_event_output()`帮助函数。
     */
    ____bpf_perf_event_output(regs, map, flags, data, size)
}
//1709-1718
// 定义返回类型和参数类型的枚举
enum RetType {
    Integer,
}

enum ArgType {
    PtrToCtx,
    ConstMapPtr,
    Anything,
    PtrToMemReadonly,
    ConstSizeOrZero,
}

// 定义函数指针类型
type BpfFunc = fn(*const u8, *const u8, u64, *const u8, usize) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
    arg4_type: ArgType,
    arg5_type: ArgType,
}

// 定义bpf_perf_event_output_tp函数
fn bpf_perf_event_output_tp(ctx: *const u8, map: *const u8, flags: u64, data: *const u8, size: usize) -> i32 {
    // 函数实现
    0
}

fn main(){
    ;
}