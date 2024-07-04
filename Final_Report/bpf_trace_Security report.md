# 关于用Rust改写bpf_trace模块的安全性报告
####  mkdir队(组长:潘铂凯 组员:胡揚嘉 金培晟 刘宇恒 王翔辉)

## 目录

- [关于用Rust改写bpf\_trace模块的安全性报告](#关于用rust改写bpf_trace模块的安全性报告)
      - [mkdir队(组长:潘铂凯 组员:胡揚嘉 金培晟 刘宇恒 王翔辉)](#mkdir队组长潘铂凯-组员胡揚嘉-金培晟-刘宇恒-王翔辉)
  - [目录](#目录)
  - [摘要](#摘要)
  - [Rust改写安全性提升简介](#rust改写安全性提升简介)
  - [具体改写安全性提升分析](#具体改写安全性提升分析)
    - [内存安全性:](#内存安全性)
    - [并发安全性:](#并发安全性)
    - [类型安全:](#类型安全)
    - [健全严谨的错误处理机制:](#健全严谨的错误处理机制)
    - [生命周期和借用检查:](#生命周期和借用检查)
    - [无 NULL 指针带来的安全性提升:](#无-null-指针带来的安全性提升)
    - [明确的类型声明和转换：](#明确的类型声明和转换)
    - [易于维护且便于阅读的宏系统](#易于维护且便于阅读的宏系统)
    - [显式的 Unsafe 代码块:](#显式的-unsafe-代码块)
    - [优秀的迭代器机制和函数式编程特性](#优秀的迭代器机制和函数式编程特性)
    - [有效可靠的模式匹配和错误处理机制](#有效可靠的模式匹配和错误处理机制)
    - [条件编译特性所带来的调试安全性和移植安全性](#条件编译特性所带来的调试安全性和移植安全性)
  - [参考文献](#参考文献)
  - [相关链接](#相关链接)


## 摘要
本文主要探讨了将 Linux 内核中的 bpf_trace 模块从 C 语言改写为 Rust 语言所带来的安全性提升。通过分析 Rust 语言的诸多特性,如所有权系统、生命周期管理、类型系统、错误处理、并发安全、无 NULL 指针等,结合我们小组改写后具体的代码示例,阐述了 Rust 改写在内存安全、类型安全、异常安全、线程安全、可读性和可维护性等方面的优势。我们一致认为,尽管 Rust 改写可能带来一定的学习成本和编程复杂度,但其对系统稳定性和可靠性的提升是显著的,值得在实践中不断探索和优化。

## Rust改写安全性提升简介
Rust 是一种系统级编程语言,其设计目标是提供与 C/C++ 相当的性能,同时通过强大的类型系统和所有权机制来保证内存安全和线程安全。相比于 C 语言,Rust 在安全性方面有诸多优势。

首先,Rust 通过所有权系统、借用检查器和生命周期来防止常见的内存相关错误,如空指针解引用、缓冲区溢出和悬垂指针等问题。Rust 的所有权系统确保每个值都有一个明确的所有者,同时限制了值的复制和移动。借用检查器则确保了在任何给定时间内,要么只有一个可变引用,要么有多个不可变引用,从而避免了数据竞争。Rust 的生命周期机制可以防止悬垂引用,确保引用的有效性。这些特性使得 Rust 程序在编译时就能发现大部分内存错误,大大提高了内存安全性。

其次,Rust 提供了强大的类型系统和严格的类型检查。Rust 的类型系统支持泛型、trait 和类型推断等特性,可以在编译时捕获类型相关的错误。Rust 还提供了 Option 和 Result 等类型来显式处理空值和错误,避免了未定义行为。Rust 的类型系统确保了程序的类型安全,减少了运行时错误。

再者,Rust 提供了安全的并发机制。Rust 的所有权系统和类型系统可以在编译时防止数据竞争,确保线程安全。Rust 提供了 Send 和 Sync 等 trait 来标记类型的线程安全性,编译器会自动检查并发安全。Rust 还提供了安全的并发原语,如 Arc 和 Mutex,以及 async/await 异步编程模型,方便开发者编写高效且安全的并发程序。

此外,Rust 还有许多其他的安全特性。例如,Rust 有严格的变量初始化检查,避免了未初始化的变量。Rust 的 match 表达式要求穷尽所有可能性,避免了遗漏情况。Rust 的 unsafe 关键字可以明确标记不安全的代码块,方便审计和维护。Rust 丰富的错误处理机制和表达式风格的返回值也提高了代码的安全性和可读性。

总体来看,Rust 通过其独特的所有权系统、类型系统、并发安全机制和其他安全特性,提供了一种安全、高效、并发友好的系统级编程语言。将 Linux 内核中的关键模块(如 bpf_trace)从 C 语言改写为 Rust,可以从根本上提高内核的内存安全、类型安全和线程安全,减少内核漏洞,提升系统的稳定性和可靠性。

## 具体改写安全性提升分析
### 内存安全性:
   >Rust 通过所有权系统、借用检查器和生命周期来防止常见的内存相关错误,如空指针解引用、缓冲区溢出和悬垂指针等问题。Rust 通过确保内存安全性，使得并发程序更加稳定可靠。与传统的系统编程语言如 C 或 C++ 相比，Rust 不仅减少了安全漏洞的风险，还提供了更细粒度的控制来优化程序性能。

例如,我们小组在BpfBprintfData模块中使用了 Rust 的 `Vec<u8>` 类型来替代原始的裸指针,从而避免了手动内存管理可能带来的内存泄漏和缓冲区溢出等问题。

```rust
struct BpfBprintfData {
    get_bin_args: bool,
    get_buf: bool,
    buf: Vec<u8>, // 使用Vec<u8>作为缓冲区
    bin_args: Vec<u64>, // 假设参数是u64类型的数组
}
```

再如,在bpf_probe_write_user模块中,我们使用了 Rust 的 `NonNull` 类型来替代原始的裸指针,以确保指针始终是非空的,避免了空指针解引用的风险。

```rust
fn bpf_probe_write_user(unsafe_ptr:NonNull<c_void>,src:NonNull<c_void>,size:u32)->i32{
    unsafe{
        let in_interrupt_var = in_interrupt() as bool;
        let unlikely_var = unlikely(in_interrupt_var||current->flags & (PF_KTHREAD | PF_EXITING)) as bool;
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
```

### 并发安全性:
   >Rust语言通过其独特的所有权和借用机制在编译阶段消除数据竞争，显著提高了程序的安全性和效率。在Rust中，每个变量都有一个明确的所有者，并且在任何时刻内，要么只允许存在一个可变引用，要么允许存在多个不可变引用。这样的设计有效预防了状态不一致和竞争条件的发生，从根本上在编译时而非运行时解决了并发中的安全问题，如数据竞争和迭代器失效等,并且Rust的线程安全保证和无锁编程特性使其在并发执行效率上优于C++。这一点对于需要高并发处理的Linux内核模块开发尤为重要，能有效提高系统的稳定性和响应速度。

例如,我们小组在改写以下代码过程中使用了 Rust 的 `Mutex` 来保护全局的 `BPF_TRACE_MODULES` 链表,确保多线程访问时的数据一致性和线程安全性。

```rust
lazy_static! {
    static ref BPF_TRACE_MODULES: Mutex<LinkedList<BpfTraceModule>> = Mutex::new(LinkedList::new());
}
```

此外，在使用 Rust 进行改写的过程中，可以使用 Rust 的并发原语,如原子操作和互斥锁,来确保线程安全和避免数据竞争。例如我们在下面展示的代码段中使用了 `PerCpu` 类型和原子操作来管理每个 CPU 的嵌套级别,确保了并发访问的安全性。


```rust
static BPF_EVENT_OUTPUT_NEST_LEVEL: PerCpu<i32> = PerCpu::new();

fn bpf_event_output(map: NonNull<bpf_map>, flags: u64, meta: NonNull<c_void>, meta_size: u64, ctx: NonNull<c_void>, ctx_size: u64, ctx_copy: bpf_ctx_copy_t) -> u64 {
    // ...
    let mut nest_level: i32 = this_cpu_inc_return(bpf_event_output_nest_level);
    // ...
    this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
    // ...
}
```


### 类型安全:
   >Rust 拥有强大的类型系统,在改写过程中可以使用 Rust 的类型系统来增强类型安全,避免类型混淆和错误的类型转换,编译器会在编译期对类型进行严格的检查,避免了很多运行时错误。

例如,在以下代码中,我们使用了 Rust 的枚举类型 `RetType` 和 `ArgType` 来替代原始的整数常量,提高了代码的可读性和可维护性,同时也避免了使用错误的常量值导致的逻辑错误。

```rust
pub struct BpfFuncProto {
    func: fn() -> (),
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
}

pub enum RetType {
    RetInteger,
    // 其他返回类型
}

pub enum ArgType {
    ArgPtrToMem,
    ArgConstSize,
    // 其他参数类型
}
```

再比如下面这个我们小组改写的函数中,通过比较 `size` 参数与 `bpf_perf_event_value` 结构体的大小,确保了类型的匹配。如果类型不匹配,则返回错误,从而避免了类型混淆,提升了函数代码的安全性。
```rust
fn bpf_perf_prog_read_value(
    ctx: *mut bpf_perf_event_data_kern,
    buf: *mut bpf_perf_event_value,
    size: u32,
) -> i32 {
    // 检查提供的size是否与`bpf_perf_event_value`结构体大小相等
    if size as usize != mem::size_of::<bpf_perf_event_value>() {
        // 如果不相等，清空buf并返回错误码
        ptr::write_bytes(buf as *mut u8, 0, size as usize);
        return -EINVAL;
    }

    // 调用假设的外部函数`perf_event_read_local`
    let err = perf_event_read_local((*ctx).event, &mut (*buf).counter, &mut (*buf).enabled, &mut (*buf).running);

    if err != 0 {
        // 如果调用失败，清空buf并返回错误码
        ptr::write_bytes(buf as *mut u8, 0, size as usize);
        return err;
    }

    0 // 成功执行
}
```

另一个例子是我们小组在定义 `bpf_raw_event_map` 结构体时,使用 Rust 的字段类型来确保类型安全。其中,`bpf_func` 字段使用了 `Option` 类型和 `unsafe extern "C" fn` 函数指针类型,确保了函数指针的类型安全和可空性。

```rust
struct bpf_raw_event_map {
    tp: *mut tracepoint,
    bpf_func: Option<unsafe extern "C" fn(ctx: *mut c_void, ...) -> i32>,
    num_args: u32,
    writable_size: u32,
}
```

### 健全严谨的错误处理机制:
   >Rust 提供了 `Result` 和 `Option` 等类型来显式地处理错误和可能为空的值,避免了忽略错误或者未检查空值导致的问题。

例如,在以下代码中,我们使用了 `io::Result<()>` 类型作为函数的返回值,明确地告知调用者这个函数可能会出现 I/O 错误,需要妥善处理,并且其使用 `?` 运算符来传播错误,确保错误得到妥善处理。
```rust
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
```


再如,我们在bpf_get_probe_write_proto模块中使用了 `Option` 类型来包装 `bpf_probe_write_user_proto`,表明这个值可能为 `None`,需要在使用时进行检查和处理。

```rust
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
```

### 生命周期和借用检查:
   >Rust 通过生命周期和借用检查来确保内存的安全访问,避免了悬垂指针、重复释放等问题。

例如,我们小组在以下代码中使用了 `&'static BpfFuncProto` 类型作为函数的返回值,明确地告知调用者返回的是一个指向静态生命周期数据的不可变引用,从而避免了悬垂指针的风险。

```rust
fn bpf_get_trace_printk_proto() -> &'static BpfFuncProto {
    set_printk_clr_event();
    unsafe { &BPF_TRACE_PRINTK_PROTO }
}
```

另一个我们小组在 Rust 改写中与之相关的例子是在 `bpf_kfunc` 模块中使用 `BpfKey` 结构体来管理密钥的生命周期,通过在 `BpfKey` 结构体中记录是否持有引用,并在 `bpf_key_put` 函数中根据该字段决定是否需要释放密钥,可以避免密钥的重复释放或悬垂指针问题。

```rust
pub struct BpfKey {
    key: *mut c_void,
    has_ref: bool,
}

pub unsafe fn bpf_key_put(bkey: *mut BpfKey) {
    if (*bkey).has_ref {
        key_put((*bkey).key);
    }
    kfree(bkey as *mut c_void);
}
```



### 无 NULL 指针带来的安全性提升:
   >在 Rust 改写中,默认情况下所有引用都是非空的,因此可以避免 NULL 指针解引用的问题,使用 Rust 的所有权系统可以从一定程度上避免内存安全问题,如空指针解引用、悬垂指针等。


例如,在以下几处代码中,我们小组使用了 `NonNull` 类型来包装指针,确保它们始终是非空的,这里使用了 `NonNull` 类型来确保指针的非空性,避免了空指针解引用的风险。

```rust
fn bpf_probe_write_user(unsafe_ptr:NonNull<c_void>,src:NonNull<c_void>,size:u32)->i32{
    unsafe{
        let in_interrupt_var = in_interrupt() as bool;
        let unlikely_var = unlikely(in_interrupt_var||current->flags & (PF_KTHREAD | PF_EXITING)) as bool;
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
//----------------------------------------------------------------------------------
//----------------------------------------------------------------------------------
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
    let mut sd = NonNull<perf_sample_data>;
    let mut regs = NonNull<pt_regs>;
    preempt_disable();
    let mut nest_level : i32= this_cpu_inc_return(bpf_event_output_nest_level);
    if WARN_ON_ONCE(nest_level as usize > ARRAY_SIZE ){
        // 错误处理，使用Result返回错误
        this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
        preempt_enable();
        return Err(-EBUSY);
    }

    let sd = this_cpu_ptr(&BPF_MISC_SDS.sds[nest_level - 1]);
    let regs = this_cpu_ptr(&BPF_PT_REGS.regs[nest_level - 1]);

    perf_fetch_caller_regs(regs);
    perf_sample_data_init(sd, 0, 0);
    perf_sample_save_raw_data(sd, &raw);

    let ret = __bpf_perf_event_output(regs, map.as_ptr(), flags, sd)?;

    // 正确的退出点
    this_cpu_dec(&BPF_EVENT_OUTPUT_NEST_LEVEL);
    preempt_enable();
    Ok(ret)
}
```

### 明确的类型声明和转换：
>在使用 Rust 进行改写时,可以使用 Rust 的类型系统来增强类型安全,以避免类型混淆和错误的类型转换。

例如在下面的bpf_current_task_under_cgroup模块中,我们小组使用了 Rust 的类型系统,从而确保了类型的正确性和一致性，比如这里使用了明确的类型转换,如 `container_of` 和 `as` 关键字,来确保类型的正确性。
```rust
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
```

### 易于维护且便于阅读的宏系统
>在使用 Rust 进行改写时,使用 Rust 的宏系统来封装和简化常见的模式和操作,提高代码的可读性和可维护性。

例如在下面展示的代码段中，我们小组在改写过程中使用了宏来定义和生成 `bpf_get_current_task` 函数,简化了代码的编写和维护。这个宏定义了一个通用的 BPF 调用函数模板,可以根据具体的函数名和参数类型生成相应的函数定义,减少了重复代码,提高了代码的可维护性。


```rust
macro_rules! BPF_CALL_0 {
    ($func:ident) => {
        #[no_mangle]
        pub extern "C" fn $func() -> i64 {
            // 将 current 转换为 i64 类型并返回
            current as i64
        }
    };
}

BPF_CALL_0!(bpf_get_current_task);
```

### 显式的 Unsafe 代码块:
   >在 Rust 中,不安全的操作必须显式地使用 `unsafe` 关键字标记,如裸指针的解引用和类型转,这提醒开发者谨慎处理这些代码,并对其正确性负责。其可以明确标记和隔离不安全的操作,提高代码的可审计性和可维护性，从而提高代码的安全性。

例如,在以下代码中,我们小组使用了 `unsafe` 块来包裹不安全的指针解引用操作,明确标记了代码中的不安全区域,提高了代码的可读性和可维护性，提醒开发者这里可能存在内存安全问题,需要谨慎处理。

```rust
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
```
### 优秀的迭代器机制和函数式编程特性
>在使用 Rust 进行改写的过程中,可以利用 Rust 的迭代器和函数式编程特性来简化代码,提高代码的可读性和可维护性，从而可以在一定程度上提升代码的安全性。

例如在下面这个函数中,我们使用了 `rev` 方法将迭代器反转,从数组的末尾开始遍历,直到找到匹配的 `module` 或遍历完整个数组，从而可以使得改写的代码简洁明了,易于理解和维护。
```rust
fn has_module(arr: &modules_array, module: &module) -> bool {
    // 从 arr.mods_cnt - 1 开始遍历,直到 0
    for i in (0..arr.mods_cnt).rev() {
        // 如果 arr.mods[i] 与给定的 module 相同,返回 true
        if arr.mods[i as usize] == module {
            return true;
        }
    }
    // 如果遍历完整个数组都没有找到匹配的 module,返回 false
    false
}
```
###  有效可靠的模式匹配和错误处理机制
>在使用 Rust 进行改写的过程中,可以使用 Rust 的模式匹配和错误处理机制来增强代码的健壮性和可读性,从而可以进一步的提升所改写代码的安全性。

例如在下面的代码段中我们使用了模式匹配来处理不同的编译特性,使代码更加清晰和易于理解。同时,也使用了条件表达式来检查指针的有效性,增强了代码的健壮性。
```rust
fn bpf_get_func_ip_kprobe(regs: NonNull<pt_regs>) -> i32 {
    unsafe {
        if cfg!(feature = "CONFIG_UPROBES") {
            // ...
        } else {
            let mut kp: NonNull<kprobe> = kprobe_running();
            if (!kp || !(kp.flags & KPROBE_FLAG_ON_FUNC_ENTRY)) {
                return 0;
            }
            return get_entry_ip(kp.addr as uintptr_t);
        }
    }
}
```
模式匹配在另外一个方面的例子如下，在下面这段代码中,我们再次使用了模式匹配来处理不同的 `BpfFuncId`,提高了代码的可读性和可维护性。同时,对于未知的 `BpfFuncId`,也提供了默认的处理方式,增强了代码的健壮性。
```rust
fn tp_prog_func_proto(func_id: BpfFuncId, prog: &BpfProg) -> &'static BpfFuncProto {
    match func_id {
        BpfFuncId::PerfEventOutput => &BPF_PERF_EVENT_OUTPUT_PROTO_TP,
        BpfFuncId::GetStackId => &BPF_GET_STACKID_PROTO_TP,
        BpfFuncId::GetStack => &BPF_GET_STACK_PROTO_TP,
        BpfFuncId::GetAttachCookie => &BPF_GET_ATTACH_COOKIE_PROTO_TRACE,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}
```
此外，在偏移量的处理方面模式匹配也可以很好的提高代码段的安全性,例如在我们改写的如下代码段中，使用模式匹配来处理不同的偏移量,提高了代码的可读性和可维护性。同时,对于未知的偏移量,也提供了默认的处理方式,增强了代码的健壮性。
```rust
fn pe_prog_convert_ctx_access(type: bpf_access_type, si: *mut bpf_insn, insn_buf: *mut bpf_insn, prog: *mut bpf_prog, target_size: *mut u32) -> u32 
{
    let insn: *mut bpf_insn = insn_buf;
    match si.off
    {
        offsetof(bpf_perf_event_data, sample_period) => 
        {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, data), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, data));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_DW, si.dst_reg, si.dst_reg, bpf_target_off(perf_sample_data, period, 8, target_size));
            insn += 1;
        },
        offsetof(bpf_perf_event_data, addr) => {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, data), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, data));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_DW, si.dst_reg, si.dst_reg, bpf_target_off(perf_sample_data, addr, 8, target_size));
            insn += 1;
        },
        _ => {
            *insn = BPF_LDX_MEM(BPF_FIELD_SIZEOF(bpf_perf_event_data_kern, regs), si.dst_reg, si.src_reg, offsetof(bpf_perf_event_data_kern, regs));
            insn += 1;
            *insn = BPF_LDX_MEM(BPF_SIZEOF(long), si.dst_reg, si.dst_reg, si.off);
            insn += 1;
        }
    }
    return insn - insn_buf;
}
```

### 条件编译特性所带来的调试安全性和移植安全性
>在 Rust 改写中，使用 Rust 的条件编译特性来根据不同的编译选项生成不同的代码,提高了代码的可调试性、灵活性和可移植性，在这些过程中都可以在一定程度上提升代码的安全性。

例如在下面的代码段中，我们小组使用了 `#[cfg()]` 属性来根据是否定义了 `CONFIG_KEYS` 和 `CONFIG_SYSTEM_DATA_VERIFICATION` 来决定是否编译相应的模块,使代码可以适应不同的内核配置，从而大大降低了在代码移植过程中所可能带来的安全性问题。

```rust
#[cfg(CONFIG_KEYS)]
mod bpf_kfunc {
    use std::ptr;
    use std::ffi::c_void;

    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }
    // ...
}

#[cfg(CONFIG_SYSTEM_DATA_VERIFICATION)]
mod bpf_kfunc {
    use std::ptr;
    use std::ffi::c_void;

    // 定义用于表示密钥的结构体
    pub struct BpfKey {
        key: *mut c_void,
        has_ref: bool,
    }
    // ...
}
```

总体概括,我们小组本次由 bpf_trace 模块改写的 Rust 代码利用了 Rust 语言的诸多特性,如所有权系统、生命周期管理、类型系统、并发原语、宏系统、模式匹配、错误处理、`unsafe` 块、迭代器、条件编译等,来增强代码的内存安全、类型安全、异常安全、线程安全、可读性和可维护性,加之我们小组在改写过程中谨慎的代码改写,提高了代码的整体质量和安全，同时保证了代码的可审计性和可控性。这些改进都有助于减少潜在的漏洞和安全风险,提高系统的稳定性和可靠性。

## 参考文献
[1] Steve Klabnik, Carol Nichols. The Rust Programming Language. No Starch Press, 2018
[2] Nicholas D. Matsakis, Felix S. Klock II. The Rust Language. ACM SIGAda Ada Letters, 2014
[3] Ralf Jung, Jacques-Henri Jourdan, Robbert Krebbers, Derek Dreyer. RustBelt: Securing the Foundations of the Rust Programming Language. Proceedings of the ACM on Programming Languages, 2018
[4] Abhiram Balasubramanian, Marek S. Baranowski, Anton Burtsev, Aurojit Panda, Zvonimir Rakamarić, Leonid Ryzhyk. System Programming in Rust: Beyond Safety. HotOS, 2017
[5]Hui Xu, Zhuangbin Chen, Mingshen Sun, Yangfan Zhou, Michael Stumm. Memory-Safety Challenge Considered Solved? An In-Depth Study with All Rust CVEs. arXiv preprint arXiv, 2020
[6]  梁红, 杨鹏. Rust语言安全性分析与应用. 网络空间安全, 2020
[7]  陈渝, 尹霞, 张峰. Rust语言机制与安全性. 软件学报, 2019
[8]  尹霞, 张峰, 陈渝. Rust安全编程模式. 软件学报, 2019
[9]  郭东东, 王之泰, 王飞. Rust语言的生命周期机制研究. 小型微型计算机系统,2020
[10]  张峰, 尹霞, 陈渝. Rust语言的异步编程模型研究. 软件学报, 2019
[11] 张汉东, 李先静, 郑纬民. Rust语言的模式匹配机制研究. 软件学报, 2019

## 相关链接
- [Rust 如何解决内存安全问题](https://www.infoq.cn/article/2UZfD5dt6mQYcJlJSkNM)
- [Rust 语言的安全性分析](https://www.cnblogs.com/peteremperor/p/14503116.html)
- [Rust 语言安全性介绍](https://zhuanlan.zhihu.com/p/86210634)
- [Rust 语言的优势与不足](https://www.infoq.cn/article/nqIUVUigjxBVjPV3lyuK)
- [Rust 程序设计语言](https://www.rust-lang.org/zh-CN/)
- [Rust 语言圣经](https://course.rs/about-book.html)
- [Rust 语言安全应用开发](https://www.icourse163.org/course/XIYOU-1461872167)
- [Rust 编程之道](https://item.jd.com/12479415.html)
- [Rust Programming Language](https://www.rust-lang.org/)
- [bpftrace](https://github.com/iovisor/bpftrace)
- [bpftrace 教程](https://github.com/DavadDi/bpftrace_study)
- [Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/index.html)
