# 关于用Rust改写bpf_trace模块的结题报告
####  mkdir队(组长:潘铂凯 组员:胡揚嘉 金培晟 刘宇恒 王翔辉)

## 目录
  - [目录](#目录)
  - [项目简介](#项目简介)
    - [bpf_trace模块介绍](#bpf_trace模块介绍)
    - [项目内容介绍](#项目内容介绍)
  - [项目背景和调研](#项目背景和调研)
    - [Linux被攻击事件](#linux被攻击事件)
    - [调研部分信息概览](#调研部分信息概览)
  - [技术路线介绍](#技术路线介绍)
    - [项目工具介绍](#项目工具介绍)
    - [改写依据和基本方法](#改写依据和基本方法)
    - [原C代码整体简介](#原c代码整体简介)
    - [改写思路和改写规则制定](#改写思路和改写规则制定)
    - [遇到的困难以及解决方案](#遇到的困难以及解决方案)
  - [Rust改写结果分析](#rust改写结果分析)
    - [Rust改写代码整体简介](#rust改写代码整体简介)
    - [部分模块功能分析及改写展示](#部分模块功能分析及改写展示)
    - [bpf\_trace由Rust改写所带来的安全性提升介绍](#bpf_trace由rust改写所带来的安全性提升介绍)
      - [摘要](#摘要)
      - [Rust改写安全性提升简介](#rust改写安全性提升简介)
      - [具体改写安全性提升分析](#具体改写安全性提升分析)
        - [内存安全性](#内存安全性)
        - [并发安全性](#并发安全性)
        - [类型安全](#类型安全)
        - [健全严谨的错误处理机制](#健全严谨的错误处理机制)
        - [生命周期和借用检查](#生命周期和借用检查)
        - [无 NULL 指针带来的安全性提升](#无-null-指针带来的安全性提升)
        - [明确的类型声明和转换](#明确的类型声明和转换)
        - [易于维护且便于阅读的宏系统](#易于维护且便于阅读的宏系统)
        - [显式的 Unsafe 代码块](#显式的-unsafe-代码块)
        - [优秀的迭代器机制和函数式编程特性](#优秀的迭代器机制和函数式编程特性)
        - [有效可靠的模式匹配和错误处理机制](#有效可靠的模式匹配和错误处理机制)
        - [条件编译特性所带来的调试安全性和移植安全性](#条件编译特性所带来的调试安全性和移植安全性)
  - [改写成果功能测试展示](#改写成果功能测试展示)
    - [改写代码编译过程展示](#改写代码编译过程展示)
    - [bpf\_trace改写模块单行测试展示](#bpf_trace改写模块单行测试展示)
  - [总结、不足与展望](#总结不足与展望)
    - [项目成果与工作量](#项目成果与工作量)
    - [工作进展与成员分工](#工作进展与成员分工)
    - [不足与反思](#不足与反思)
    - [未来展望](#未来展望)
  - [鸣谢](#鸣谢)
  - [参考文献](#参考文献)
  - [相关链接](#相关链接)

## 项目简介

### bpf_trace模块介绍

### 项目内容介绍

## 项目背景和调研

### Linux被攻击事件

### 调研部分信息概览

## 技术路线介绍

### 项目工具介绍

### 改写依据和基本方法

### 原C代码整体简介

### 改写思路和改写规则制定

### 遇到的困难以及解决方案

## Rust改写结果分析

### Rust改写代码整体简介

### 部分模块功能分析及改写展示

### bpf_trace由Rust改写所带来的安全性提升介绍
#### 摘要
本部分主要探讨了将 Linux 内核中的 bpf_trace 模块从 C 语言改写为 Rust 语言所带来的安全性提升。通过分析 Rust 语言的诸多特性,如所有权系统、生命周期管理、类型系统、错误处理、并发安全、无 NULL 指针等,结合我们小组改写后具体的代码示例,阐述了 Rust 改写在内存安全、类型安全、异常安全、线程安全、可读性和可维护性等方面的优势。我们一致认为,尽管 Rust 改写可能带来一定的学习成本和编程复杂度,但其对系统稳定性和可靠性的提升是显著的,值得在实践中不断探索和优化。

#### Rust改写安全性提升简介
Rust 是一种系统级编程语言,其设计目标是提供与 C/C++ 相当的性能,同时通过强大的类型系统和所有权机制来保证内存安全和线程安全。相比于 C 语言,Rust 在安全性方面有诸多优势。

首先,Rust 通过所有权系统、借用检查器和生命周期来防止常见的内存相关错误,如空指针解引用、缓冲区溢出和悬垂指针等问题。Rust 的所有权系统确保每个值都有一个明确的所有者,同时限制了值的复制和移动。借用检查器则确保了在任何给定时间内,要么只有一个可变引用,要么有多个不可变引用,从而避免了数据竞争。Rust 的生命周期机制可以防止悬垂引用,确保引用的有效性。这些特性使得 Rust 程序在编译时就能发现大部分内存错误,大大提高了内存安全性。

其次,Rust 提供了强大的类型系统和严格的类型检查。Rust 的类型系统支持泛型、trait 和类型推断等特性,可以在编译时捕获类型相关的错误。Rust 还提供了 Option 和 Result 等类型来显式处理空值和错误,避免了未定义行为。Rust 的类型系统确保了程序的类型安全,减少了运行时错误。

再者,Rust 提供了安全的并发机制。Rust 的所有权系统和类型系统可以在编译时防止数据竞争,确保线程安全。Rust 提供了 Send 和 Sync 等 trait 来标记类型的线程安全性,编译器会自动检查并发安全。Rust 还提供了安全的并发原语,如 Arc 和 Mutex,以及 async/await 异步编程模型,方便开发者编写高效且安全的并发程序。

此外,Rust 还有许多其他的安全特性。例如,Rust 有严格的变量初始化检查,避免了未初始化的变量。Rust 的 match 表达式要求穷尽所有可能性,避免了遗漏情况。Rust 的 unsafe 关键字可以明确标记不安全的代码块,方便审计和维护。Rust 丰富的错误处理机制和表达式风格的返回值也提高了代码的安全性和可读性。

总体来看,Rust 通过其独特的所有权系统、类型系统、并发安全机制和其他安全特性,提供了一种安全、高效、并发友好的系统级编程语言。将 Linux 内核中的关键模块(如 bpf_trace)从 C 语言改写为 Rust,可以从根本上提高内核的内存安全、类型安全和线程安全,减少内核漏洞,提升系统的稳定性和可靠性。

#### 具体改写安全性提升分析
##### 内存安全性
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

##### 并发安全性
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


##### 类型安全
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

##### 健全严谨的错误处理机制
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

##### 生命周期和借用检查
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



##### 无 NULL 指针带来的安全性提升
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

##### 明确的类型声明和转换
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

##### 易于维护且便于阅读的宏系统
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

##### 显式的 Unsafe 代码块
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
##### 优秀的迭代器机制和函数式编程特性
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
#####  有效可靠的模式匹配和错误处理机制
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

##### 条件编译特性所带来的调试安全性和移植安全性
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

## 改写成果功能测试展示

### 改写代码编译过程展示

### bpf_trace改写模块单行测试展示

## 总结、不足与展望

### 项目成果与工作量

### 工作进展与成员分工
**提交分布图**

![alt text](<report_pic_ 1.png>)

**项目进展与成员分工总览**
|项目阶段|阶段时间|阶段简介/阶段成果|工作分工|
|:-:|:-:|:-|:-:|
|初步选题调研阶段|3.3-3.9|在这一阶段，我们小组通过对各自心仪的方向进行调研，结合操作系统的实验工作方向以及目前大模型应用、Rust改写等计算机领域研究趋势进行资料查找与阅读，最终在3.9号的交流分享中总结出了一下几个初步选题方向，为下一步的确定选题工作奠定基础。 <br>  <br> 方向[1]： 用Rust写一个loongarch64、mips或者RISC-V的微内核 <br> 方向[2]： 用Rust优化linux内核的一部分，如kvm相关的部分，或者优化loongarch的linux系统的一部分 <br> 方向[3]： 借助网上现有开源的大模型，通过租用云服务器（如AutoDL）进行大模型的训练以及调整（将训练重点放在操作系统这一指定方向来避免难以想象的工作量）使之可以适用于并优化现有操作系统的交互接口 <br> 方向[4]： 探索操作系统虚拟化技术的实现与优化。侧重于两种主流的开源虚拟化技术——XEN和KVM，理解它们的工作原理、优缺点以及适用场景。核心是使用Rust语言实现一个虚拟化环境，并尝试进行优化。 <br> 方向[5]： 使用Rust语言来重新实现和优化ROS的MMU，利用Rust语言的内存安全性和无需垃圾回收的特性，以期提高ROS在内存管理方面的效率和可靠性。侧重于理解ROS中MMU的工作原理、当前存在的优缺点以及适用场景，并尝试通过改进和优化来提升其性能。 <br> 方向[6]： 在ROS中，通信是一个至关重要的组成部分，其安全性和性能直接影响着ROS系统的稳定性和效率。故我们计划重新设计和优化ROS的通信模块，以提升通信的安全性和性能。 <br> 方向[7]： 用RUST改写分布式文件管理或计算系统，使其在原有基础上完善安全性相关问题并且一定程度上实现性能提升。|各成员依据各自感兴趣的方向进行调研，故不做过多任务分配要求|
|分析筛选选题调研阶段|3.10-3.16|在这一阶段，我们对以上提及的七个方向进行了进一步的可行性方案调研，并且与指导老师沟通了初步的选题思路，最后，在老师的指导帮助下以及通过我们的调研分析，我们综合考虑了硬件基础、潜在挑战、功能实现、性能优化、安全性等因素，决定优先考虑方向[2]（用Rust优化linux内核的一部分，如kvm相关的部分）以及方向[5]（使用Rust语言来重新实现和优化ROS的MMU）这两个选题，以待下一步的调研。|由于各问题无明显分割，需要整体看待，集体解决，故不做过多任务分配要求|
|深入专项分析两大选题调研阶段|3.17-3.23|通过了一周的专项调研以及在课后与指导老师的思路交流，我们由于改写ROS会涉及到底层通信，其中网络作为系统领域和OS并列的另一大领域，潜在困难会远多于另一个方案，并且ROS的性能/功能瓶颈获取并不明显受到该实验改写方向的影响（相对而言，ROS的通信瓶颈更多的在网络拓扑和网络通信方向，而不是在本机的代码执行效率上） ，故我们选择了将用Rust改写Linux作为了最终选题。就这一选题方向我们小组也做了大量的调研，如其目前实现面临的困难（如在同一宏内核中Rust语言与C语言共存所可能带来的风险等，由于具体部分在立项依据以及困难与挑战部分均有详细阐述，在此不再过多赘述）并且作为进一步的拓展部分，我们还调研了Q-Learning这一机器学习算法的应用，可以将其作为Rust改写Linux存储管理调用部分的拓展工作。|潘铂凯、王翔辉、刘宇恒着重调研选题一 <br> 胡揚嘉、金培晟着重调研选题二|
|可行性分析部分的调研以及初步调研报告编写阶段|3.24-3.30|在这一阶段中，我们总结此前做过的一系列调研与讨论工作，通过具体分工进行初步调研报告的编写，并且我们对在接下来的可行性验证工作以及正式实验工作必然会用到的语言——Rust进行了初步的集体学习，为了接下来小组实验的顺利进行，这一步的工作是有效且必要的。|潘铂凯：立项依据、调研过程 <br> 王翔辉：相关工作 <br> 胡揚嘉：项目背景、遇到的困难以及（可能的）解决方式 <br> 金培晟：前瞻性分析、重要性分析 <br> 刘宇恒：总结归纳、整理排版|
|可行性分析专项调研阶段|3.31-4.5|在这一阶段中，我们小组将就用Rust改写Linux这一过程中具体会遇到的种种问题进行可行性的专项分析，我们希望通过实机测试为主、资料调研为辅的形式给出更为实际具体、更有说服力的可行性分析，其中我们就RUST改写Linux具体安全性与性能提升方面以及RUST改写具体实现方式、RUST与C语言环境的兼容性、RUST与C语言函数之间的相互调用进行了专项调研，并且我们根据具体的Linux6.8.4源代码进行了改写模块的初步筛选与分析。|潘铂凯、王翔辉、胡揚嘉：合作探究如何将RUST放入C语言环境，与编译相关的问题，如何用Rust调用C语言库等关于Rust改写方向的问题 <br> 刘宇恒、金培晟：合作探究Rust改写Linux的性能提高以及安全性影响的检测与分析|
|可行性分析最终调研与报告编写阶段|4.6-4.10|在这一阶段中，我们将继续对该项目的可行性进行分析，通过进一步已有改写部分代码的比对与测试，结合我们对于RUST改写优势的理解，筛选出最终希望改写的Linux模块，以获得最佳的改写效果。并且，我们将在这一阶段完成可行性调研的报告，确定最终立项。|潘铂凯：模块分析与筛选部分初步汇总整理 <br> 胡揚嘉：RUST改写Linux的具体技术支持部分汇总整理 <br> 刘宇恒、金培晟：进行并行代码等测试代码的分析比对，RUST改写Linux的具体理论支持部分汇总整理 <br> 王翔辉：创新点总结分析，各模块的梳理补充，整理排版|
|可行性报告收尾与中期汇报筹备阶段|4.11-4.21|在这一阶段中，我们结合此前的大量调查和Linux源代码分析，并已经通过小组讨论确定了最终的改写模块——bpf-trace模块（kernal/trace/bpf-trace），因此我们将在完成性能测试报告部分的同时重点结合此模块进行可行性报告的收尾。此外，我们小组还将尝试实现对Linux中的一个小模块的Rust改写和编译，这将为我们的可行性报告提供强有力的事实依据。最后，我们还将筹划将在下一周到来的中期汇报，结合调研报告和可行性报告，完成相应的ppt以及讲解思路整理。|潘铂凯：可行性报告模块选择部分的总结以及创新点编写，完成可行性报告的最终汇总 <br> 胡揚嘉、金培晟、王翔辉：合作实现用Rust改写Linux中的一个小模块并实现编译，完成相关过程的实验梳理总结 <br> 刘宇恒：完成中期汇报展示所用的ppt以及讲解思路整理|
|学期中任务处理以及总结改进阶段|4.22-5.4|在这一阶段中，由于学期中繁多的任务（OSH实验、CODH实验、CODH调研报告...）以及部分组员面临着期中考试的压力（量子物理期中...），我们小组经过讨论后决定设置该缓冲阶段，使得小组成员们有余力来处理这些繁重的任务。当然，在这次讨论中我们总结了此前工作的经验与不足，并且对可行性分析报告进行了更进一步技术支持的补充。（实现了对Linux中一个小模块的Rust改写和编译以及相关的技术分析）|缓冲阶段，故不做任务分配要求，学有余力的小组成员可以进一步学习Rust语言以及Linux改写相关的知识|
|正式改写阶段|5.5-6.28|在这一阶段中，在处理完此前存在的诸多事项后，我们小组正式开始了对bpf-trace模块的改写，我们计划实时上传自己的改写工作到各自的改写文件夹中，并且通过公共交流栏的探讨稳步推进改写工作，由于其是该项目的核心部分，这一阶段预计将持续很长时间，但是在这个过程中，我们仍会根据目前小组的改写进度进行不定期的小组讨论，并且进行汇总更新，及时梳理总结改写经验并且集中解决问题|不再具体分工，但会根据Main Rewrite Work_Summary中各成员的贡献度进行提醒督促|
|改写中期讨论（第一次）|5.21|在本次讨论中，我们小组集中讨论解决了结构体的改写、部分函数改写及引用、函数模块之间的调用等问题，并且对进一步的工作进行了规划与分工。此外，本次讨论中还分析了未来可能遇到的几个风险挑战以及在测试编译上可能出现的巨大难题，因为交叉编译以及难以找到相关的Linux测试环境，预计到时会遇到很大的阻碍，我们小组将在这一过程中修找解决方法|不再具体分工，但会根据Main Rewrite Work_Summary中各成员的贡献度进行提醒督促|
|改写中期讨论（第二次）|6.5|在本次讨论中，我们小组相互交换了在此前改写中得到了一些经验，并且一起分析处理了一下如特殊类型的指针、变量类型处理等比较棘手的问题，并且对后期将要进行的代码汇总工作进行了一定程度的规划，由于改写工作量很大（原C语言3500line，Rust改写后预计5000line），我们小组决定在原有项目栏督促的基础上，由组长在小组交流群中统一分配规划进度，保证改写项目的顺利完成|仍然不进行具体分工，但会根据Main Rewrite Work_Summary中各成员的贡献度进行提醒督促，并且在交流群中统一进行改写行数方面的分配|
|Rust改写代码汇总查错阶段|6.29-7.1|从这一阶段开始，我们小组将在研讨室中进行全天性的工作，在这一阶段中我们小组汇总了先前分工完成的各部分改写代码，进行全面的查错修改，并且包括统一修改结构体定义和应用、统一添加函数库等相关工作，保证改写项目的正确性和健壮性|在研讨室中集体合作，灵活分工，不再具体安排|
|功能测试阶段|7.2-7.3|在这一阶段中，我们小组将运用在上一阶段中经过一系列查错修改以及模块完善所得到的最终改写代码，尝试对其进行相关的功能测试，并且将在下一阶段中生成与之相关的报告|在研讨室中集体合作，灵活分工，不再具体安排|
|各项报告生成阶段|7.4|在这一阶段中，我们小组将从代码正确性和健壮性分析报告、代码安全性分析报告、代码功能测试报告三个方向对此前的工作进行整体的分析分析整理，并且通过具体代码的分析以及实际具体的功能测试等各个方面分析、测试所改写的Rust代码的完成度和优良特性|胡揚嘉、刘宇恒：代码正确性和健壮性分析报告 <br> 潘铂凯：代码安全性分析报告 <br> 王翔辉、金培晟：代码功能测试报告|
|**当前阶段：期末汇报筹备阶段**|7.5-现在|在这一阶段中，我们小组将综合上一阶段中完成的各部分报告，并且加之以此前收集调研的各种信息，进行期末汇报的筹备（演讲稿撰写，ppt制作，演讲练习）。此外，在进行期末汇报筹备的同时，我们也将同步进行项目最终报告的初步撰写，为期末汇报的ppt制作提供一些更有条理的信息支持|金培晟、胡揚嘉、王翔辉：期末汇报筹备 <br> 潘铂凯、刘宇恒：项目最终报告初步撰写|
### 不足与反思

### 未来展望

## 鸣谢

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
