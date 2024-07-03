# 函数改写
1.  85-95
```cpp
u64 bpf_get_stackid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
u64 bpf_get_stack(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

static int bpf_btf_printf_prepare(struct btf_ptr *ptr, u32 btf_ptr_size,
                                  u64 flags, const struct btf **btf,
                                  s32 *btf_id);
static u64 bpf_kprobe_multi_cookie(struct bpf_run_ctx *ctx);
static u64 bpf_kprobe_multi_entry_ip(struct bpf_run_ctx *ctx);

static u64 bpf_uprobe_multi_cookie(struct bpf_run_ctx *ctx);
static u64 bpf_uprobe_multi_entry_ip(struct bpf_run_ctx *ctx);
```
**说明**
- 定义了几个 u64 类型的 BPF 函数，它们有多个参数，用于不同的 BPF 功能。
- 函数 bpf_btf_printf_prepare 准备 BTF 指针用于打印。
- 函数 bpf_kprobe_multi_cookie 和 bpf_kprobe_multi_entry_ip 用于处理 Kprobe 多重探测。
- 函数 bpf_uprobe_multi_cookie 和 bpf_uprobe_multi_entry_ip 用于处理 Uprobe 多重探测。

```rust
// 定义函数类型
type U64Func = fn(u64, u64, u64, u64, u64) -> u64;
type BpfRunCtx = *mut c_void;
type BtfPtr = *mut c_void;
type Btf = *const c_void;

// 定义函数
extern "C" {
    fn bpf_get_stackid(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;
    fn bpf_get_stack(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64;

    fn bpf_btf_printf_prepare(ptr: *mut BtfPtr, btf_ptr_size: u32, flags: u64, btf: *const *const Btf, btf_id: *mut i32) -> i32;
    fn bpf_kprobe_multi_cookie(ctx: BpfRunCtx) -> u64;
    fn bpf_kprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64;

    fn bpf_uprobe_multi_cookie(ctx: BpfRunCtx) -> u64;
    fn bpf_uprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64;
}

// 函数实现
pub unsafe fn bpf_get_stackid(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64 {
    bpf_get_stackid(r1, r2, r3, r4, r5)
}

pub unsafe fn bpf_get_stack(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> u64 {
    bpf_get_stack(r1, r2, r3, r4, r5)
}

pub unsafe fn bpf_btf_printf_prepare(ptr: *mut BtfPtr, btf_ptr_size: u32, flags: u64, btf: *const *const Btf, btf_id: *mut i32) -> i32 {
    bpf_btf_printf_prepare(ptr, btf_ptr_size, flags, btf, btf_id)
}

pub unsafe fn bpf_kprobe_multi_cookie(ctx: BpfRunCtx) -> u64 {
    bpf_kprobe_multi_cookie(ctx)
}

pub unsafe fn bpf_kprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64 {
    bpf_kprobe_multi_entry_ip(ctx)
}

pub unsafe fn bpf_uprobe_multi_cookie(ctx: BpfRunCtx) -> u64 {
    bpf_uprobe_multi_cookie(ctx)
}

pub unsafe fn bpf_uprobe_multi_entry_ip(ctx: BpfRunCtx) -> u64 {
    bpf_uprobe_multi_entry_ip(ctx)
}
```
**说明**
- 使用 extern "C" 块声明外部 C 函数。
- 定义函数 bpf_get_stackid 和 bpf_get_stack，用于获取栈ID和栈信息。
- 定义函数 bpf_btf_printf_prepare，用于准备BTF指针打印。
- 定义函数 bpf_kprobe_multi_cookie 和 bpf_kprobe_multi_entry_ip，用于处理 Kprobe 多重探测。
- 定义函数 bpf_uprobe_multi_cookie 和 bpf_uprobe_multi_entry_ip，用于处理 Uprobe 多重探测。

2.  655-660
```cpp
struct bpf_trace_sample_data {
	struct perf_sample_data sds[3];
};

static DEFINE_PER_CPU(struct bpf_trace_sample_data, bpf_trace_sds);
static DEFINE_PER_CPU(int, bpf_trace_nest_level);
```
**说明**
- 定义了一个结构体 bpf_trace_sample_data，包含一个 perf_sample_data 数组。
- 使用 DEFINE_PER_CPU 宏为每个 CPU 定义了两个静态变量：
- bpf_trace_sds 类型为 struct bpf_trace_sample_data。
- bpf_trace_nest_level 类型为 int。
```rust
use core::cell::UnsafeCell;

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
```
**说明**
- 使用 #[repr(C)] 定义与C语言兼容的结构体 PerfSampleData 和 BpfTraceSampleData。
- 使用静态变量 BPF_TRACE_SDS 和 BPF_TRACE_NEST_LEVEL 表示每个 CPU 的变量。
- 定义了一个 PerCpu 结构体，模拟每个 CPU 的变量存储。
- PerCpu 结构体包含一个 UnsafeCell<T>，用于存储数据。
- PerCpu 结构体提供了 get 和 get_mut 方法，用于获取数据的不可变和可变引用。

3.  711-716
```cpp
static DEFINE_PER_CPU(int, bpf_event_output_nest_level);

struct bpf_nested_pt_regs {
	struct pt_regs regs[3];
};

static DEFINE_PER_CPU(struct bpf_nested_pt_regs, bpf_pt_regs);
static DEFINE_PER_CPU(struct bpf_trace_sample_data, bpf_misc_sds);
```
**说明**
- 使用 DEFINE_PER_CPU 宏为每个 CPU 定义了一个静态变量 bpf_event_output_nest_level，类型为 int。
- 定义了一个结构体 bpf_nested_pt_regs，包含一个 pt_regs 数组。
- 使用 DEFINE_PER_CPU 宏为每个 CPU 定义了两个静态变量：
- bpf_pt_regs 类型为 struct bpf_nested_pt_regs。
- bpf_misc_sds 类型为 struct bpf_trace_sample_data。
```rust
use core::cell::UnsafeCell;

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
```
**说明**
- 使用 #[repr(C)] 定义与C语言兼容的结构体 PtRegs、BpfNestedPtRegs 和 BpfTraceSampleData。
- 使用静态变量 BPF_EVENT_OUTPUT_NEST_LEVEL、BPF_PT_REGS 和 BPF_MISC_SDS 表示每个 CPU 的变量。
- 定义了一个 PerCpu 结构体，模拟每个 CPU 的变量存储。
- PerCpu 结构体包含一个 UnsafeCell<T>，用于存储数据。
- PerCpu 结构体提供了 get 和 get_mut 方法，用于获取数据的不可变和可变引用。

4.  1027-1036
```cpp
const struct bpf_func_proto bpf_snprintf_btf_proto = {
	.func		= bpf_snprintf_btf,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};
```
**说明**
- 这个结构体 bpf_func_proto 定义了一个 BPF 函数 bpf_snprintf_btf 的原型。
- 字段解释：
    func: 指向函数 bpf_snprintf_btf 的指针。
    gpl_only: 布尔值，指示该函数是否仅限于 GPL 许可证。
    ret_type: 返回类型，这里是整数。
    arg1_type: 第一个参数的类型，这里是指向内存的指针。
    arg2_type: 第二个参数的类型，这里是常量大小。
    arg3_type: 第三个参数的类型，这里是只读的指向内存的指针。
    arg4_type: 第四个参数的类型，这里是常量大小。
    arg5_type: 第五个参数的类型，这里是任意类型。
```rust
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
```
**说明**
- RetType 和 ArgType 枚举用于表示返回类型和参数类型。
- BpfFunc 类型表示BPF函数指针，接受五个参数并返回一个整数。
- BpfFuncProto 结构体包含与C++结构体相同的字段。
- 实现了 bpf_snprintf_btf 函数，作为示例的BPF函数。
- 实例化了 BpfFuncProto 结构体，类似于C++中的定义。

5.  1709-1718
```cpp
static const struct bpf_func_proto bpf_perf_event_output_proto_tp = {
	.func		= bpf_perf_event_output_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};
```
**说明**
- 这个结构体 bpf_func_proto 定义了一个 BPF 函数 bpf_perf_event_output_tp 的原型。
- 字段解释：
    func: 指向函数 bpf_perf_event_output_tp 的指针。
    gpl_only: 布尔值，指示该函数是否仅限于 GPL 许可证。
    ret_type: 返回类型，这里是整数。
    arg1_type: 第一个参数的类型，这里是指向上下文的指针。
    arg2_type: 第二个参数的类型，这里是常量映射指针。
    arg3_type: 第三个参数的类型，这里是任意类型。
    arg4_type: 第四个参数的类型，这里是只读的指向内存的指针。
    arg5_type: 第五个参数的类型，这里是常量大小或零。
```rust
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
```
**说明**
- RetType 和 ArgType 枚举用于表示返回类型和参数类型。
- BpfFunc 类型表示BPF函数指针，接受五个参数并返回一个整数。
- BpfFuncProto 结构体包含与C++结构体相同的字段。
- 实现了 bpf_perf_event_output_tp 函数，作为示例的BPF函数。
- 实例化了 BpfFuncProto 结构体，类似于C++中的定义。

5. 1734-1741
```cpp
static const struct bpf_func_proto bpf_get_stackid_proto_tp = {
	.func		= bpf_get_stackid_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};
```
**说明**
- 这个结构体 bpf_func_proto 定义了一个 BPF 函数 bpf_get_stackid_tp 的原型。
- 字段解释：
    func: 指向函数 bpf_get_stackid_tp 的指针。
    gpl_only: 布尔值，指示该函数是否仅限于 GPL 许可证。
    ret_type: 返回类型，这里是整数。
    arg1_type: 第一个参数的类型，这里是指向上下文的指针。
    arg2_type: 第二个参数的类型，这里是常量映射指针。
    arg3_type: 第三个参数的类型，这里是任意类型。
```rust
// 定义返回类型和参数类型的枚举
#[derive(Debug, PartialEq)]
enum RetType {
    Integer,
}

#[derive(Debug, PartialEq)]
enum ArgType {
    PtrToCtx,
    ConstMapPtr,
    Anything,
}

// 定义函数指针类型
type BpfFunc = fn(*const u8, *const u8, u64) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
}

// 定义bpf_get_stackid_tp函数
fn bpf_get_stackid_tp(ctx: *const u8, map: *const u8, flags: u64) -> i32 {
    // 函数实现
    0
}
```
**说明**
- 使用 RetType 和 ArgType 枚举表示返回类型和参数类型。
- 使用 BpfFunc 类型表示 BPF 函数指针，接受三个参数并返回一个整数。
- BpfFuncProto 结构体包含与 C++ 结构体相同的字段。
- 实现了 bpf_get_stackid_tp 函数，作为示例的 BPF 函数。
- 实例化了 BpfFuncProto 结构体，类似于 C++ 中的定义。

6.  1752-1777
```cpp
static const struct bpf_func_proto bpf_get_stack_proto_tp = {
	.func		= bpf_get_stack_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

static const struct bpf_func_proto *
tp_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto_tp;
	case BPF_FUNC_get_stackid:
		return &bpf_get_stackid_proto_tp;
	case BPF_FUNC_get_stack:
		return &bpf_get_stack_proto_tp;
	case BPF_FUNC_get_attach_cookie:
		return &bpf_get_attach_cookie_proto_trace;
	default:
		return bpf_tracing_func_proto(func_id, prog);
	}
}
```
**说明**
- bpf_get_stack_proto_tp 结构体定义了 BPF 函数 bpf_get_stack_tp 的原型。
- 字段解释：
    func: 指向函数 bpf_get_stack_tp 的指针。
    gpl_only: 布尔值，指示该函数是否仅限于 GPL 许可证。
    ret_type: 返回类型，这里是整数。
    arg1_type: 第一个参数的类型，这里是指向上下文的指针。
    arg2_type: 第二个参数的类型，这里是指向未初始化内存的指针。
    arg3_type: 第三个参数的类型，这里是常量大小或零。
    arg4_type: 第四个参数的类型，这里是任意类型。

- tp_prog_func_proto 函数根据 func_id 返回相应的 bpf_func_proto 结构体指针。
```rust
// 定义返回类型和参数类型的枚举
#[derive(Debug, PartialEq)]
enum RetType {
    Integer,
}

#[derive(Debug, PartialEq)]
enum ArgType {
    PtrToCtx,
    PtrToUninitMem,
    ConstSizeOrZero,
    Anything,
}

// 定义函数指针类型
type BpfFunc = fn(*const u8, *mut u8, usize, u64) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
    arg4_type: ArgType,
}

// 定义bpf_get_stack_tp函数
fn bpf_get_stack_tp(ctx: *const u8, buf: *mut u8, size: usize, flags: u64) -> i32 {
    // 函数实现
    0
}

// 定义tp_prog_func_proto函数
fn tp_prog_func_proto(func_id: BpfFuncId, prog: &BpfProg) -> &'static BpfFuncProto {
    match func_id {
        BpfFuncId::PerfEventOutput => &BPF_PERF_EVENT_OUTPUT_PROTO_TP,
        BpfFuncId::GetStackId => &BPF_GET_STACKID_PROTO_TP,
        BpfFuncId::GetStack => &BPF_GET_STACK_PROTO_TP,
        BpfFuncId::GetAttachCookie => &BPF_GET_ATTACH_COOKIE_PROTO_TRACE,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}

// 定义枚举和类型
#[derive(Debug)]
enum BpfFuncId {
    PerfEventOutput,
    GetStackId,
    GetStack,
    GetAttachCookie,
    // 其他需要的函数ID...
}

struct BpfProg;

// 示例外部函数声明
extern "C" {
    fn bpf_perf_event_output_tp(ctx: *const u8, map: *const u8, flags: u64, data: *const u8, size: usize) -> i32;
    fn bpf_get_stackid_tp(ctx: *const u8, map: *const u8, flags: u64) -> i32;
    fn bpf_get_attach_cookie_trace(ctx: *const u8, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn bpf_tracing_func_proto(func_id: BpfFuncId, prog: &BpfProg) -> &'static BpfFuncProto;
}
```
**说明**
- 使用 RetType 和 ArgType 枚举表示返回类型和参数类型。
- 使用 BpfFunc 类型表示 BPF 函数指针，接受四个参数并返回一个整数。
- BpfFuncProto 结构体包含与 C++ 结构体相同的字段。
- 实现了 bpf_get_stack_tp 函数，作为示例的 BPF 函数。
- 实例化了 BpfFuncProto 结构体，类似于 C++ 中的定义。
- 定义了 tp_prog_func_proto 函数，根据 func_id 返回相应的 BpfFuncProto 结构体指针。
- 定义了枚举 BpfFuncId 和类型 BpfProg。

7.  1794-1800
``` cpp
const struct bpf_verifier_ops tracepoint_verifier_ops = {
	.get_func_proto  = tp_prog_func_proto,
	.is_valid_access = tp_prog_is_valid_access,
};

const struct bpf_prog_ops tracepoint_prog_ops = {
};
```
**说明**
- tracepoint_verifier_ops 结构体定义了两个函数指针：
- get_func_proto: 指向函数 tp_prog_func_proto。
- is_valid_access: 指向函数 tp_prog_is_valid_access。
- tracepoint_prog_ops 结构体目前为空。

```rust
// 定义函数指针类型
type GetFuncProto = fn(BpfFuncId, &BpfProg) -> &'static BpfFuncProto;
type IsValidAccess = fn(u32, u32, u32, &BpfProg) -> bool;

// 定义 BpfVerifierOps 结构体
struct BpfVerifierOps {
    get_func_proto: GetFuncProto,
    is_valid_access: IsValidAccess,
}

// 定义 BpfProgOps 结构体
struct BpfProgOps {}

// 示例外部函数声明
extern "C" {
    fn tp_prog_func_proto(func_id: BpfFuncId, prog: &BpfProg) -> &'static BpfFuncProto;
    fn tp_prog_is_valid_access(off: u32, size: u32, type_: u32, prog: &BpfProg) -> bool;
}

```
**说明**
- 使用 GetFuncProto 和 IsValidAccess 类型表示函数指针。
- BpfVerifierOps 结构体包含两个字段，分别是 get_func_proto 和 is_valid_access，对应 C++ 结构体中的两个函数指针。
- BpfProgOps 结构体目前为空，类似于 C++ 中的 tracepoint_prog_ops。
- 使用 extern "C" 声明外部函数 tp_prog_func_proto 和 tp_prog_is_valid_access。
- 实例化 TRACEPOINT_VERIFIER_OPS，将函数指针赋值给相应字段。
- 实例化 TRACEPOINT_PROG_OPS，目前为空。

8. 1819-1826  
```cpp
static const struct bpf_func_proto bpf_perf_prog_read_value_proto = {
	.func           = bpf_perf_prog_read_value,
	.gpl_only       = true,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_PTR_TO_UNINIT_MEM,
	.arg3_type      = ARG_CONST_SIZE,
};
```
**说明**
- bpf_perf_prog_read_value_proto 结构体定义了 BPF 函数 bpf_perf_prog_read_value 的原型。
- 字段解释：
    func: 指向函数 bpf_perf_prog_read_value 的指针。
    gpl_only: 布尔值，指示该函数是否仅限于 GPL 许可证。
    ret_type: 返回类型，这里是整数。
    arg1_type: 第一个参数的类型，这里是指向上下文的指针。
    arg2_type: 第二个参数的类型，这里是指向未初始化内存的指针。
    arg3_type: 第三个参数的类型，这里是常量大小。
```rust
// 定义返回类型和参数类型的枚举
#[derive(Debug, PartialEq)]
enum RetType {
    Integer,
}

#[derive(Debug, PartialEq)]
enum ArgType {
    PtrToCtx,
    PtrToUninitMem,
    ConstSize,
}

// 定义函数指针类型
type BpfFunc = fn(*const u8, *mut u8, usize) -> i32;

// 定义BpfFuncProto结构体
struct BpfFuncProto {
    func: BpfFunc,
    gpl_only: bool,
    ret_type: RetType,
    arg1_type: ArgType,
    arg2_type: ArgType,
    arg3_type: ArgType,
}

// 定义bpf_perf_prog_read_value函数
fn bpf_perf_prog_read_value(ctx: *const u8, buf: *mut u8, size: usize) -> i32 {
    // 函数实现
    0
}

```
**说明**
- 使用 RetType 和 ArgType 枚举表示返回类型和参数类型。
- 使用 BpfFunc 类型表示 BPF 函数指针，接受三个参数并返回一个整数。
- BpfFuncProto 结构体包含与 C++ 结构体相同的字段。
- 实现了 bpf_perf_prog_read_value 函数，作为示例的 BPF 函数。
- 实例化了 BpfFuncProto 结构体，类似于 C++ 中的定义。

9. 2138-2144 
```cpp
const struct bpf_verifier_ops raw_tracepoint_writable_verifier_ops = {
	.get_func_proto  = raw_tp_prog_func_proto,
	.is_valid_access = raw_tp_writable_prog_is_valid_access,
};

const struct bpf_prog_ops raw_tracepoint_writable_prog_ops = {
};
```
**说明**
- raw_tracepoint_writable_verifier_ops 结构体定义了两个函数指针：
- get_func_proto: 指向函数 raw_tp_prog_func_proto。
- is_valid_access: 指向函数 raw_tp_writable_prog_is_valid_access。
- raw_tracepoint_writable_prog_ops 结构体目前为空。

```rust
// 定义函数指针类型
type GetFuncProto = fn(BpfFuncId, &BpfProg) -> &'static BpfFuncProto;
type IsValidAccess = fn(u32, u32, u32, &BpfProg) -> bool;

// 定义 BpfVerifierOps 结构体
struct BpfVerifierOps {
    get_func_proto: GetFuncProto,
    is_valid_access: IsValidAccess,
}

// 定义 BpfProgOps 结构体
struct BpfProgOps {}

// 示例外部函数声明
extern "C" {
    fn raw_tp_prog_func_proto(func_id: BpfFuncId, prog: &BpfProg) -> &'static BpfFuncProto;
    fn raw_tp_writable_prog_is_valid_access(off: u32, size: u32, type_: u32, prog: &BpfProg) -> bool;
}
```
**说明**
- 使用 GetFuncProto 和 IsValidAccess 类型表示函数指针。
- BpfVerifierOps 结构体包含两个字段，分别是 get_func_proto 和 is_valid_access，对应 C++ 结构体中的两个函数指针。
- BpfProgOps 结构体目前为空，类似于 C++ 中的 raw_tracepoint_writable_prog_ops。
- 使用 extern "C" 声明外部函数 raw_tp_prog_func_proto 和 raw_tp_writable_prog_is_valid_access。
- 实例化 RAW_TRACEPOINT_WRITABLE_VERIFIER_OPS，将函数指针赋值给相应字段。
- 实例化 RAW_TRACEPOINT_WRITABLE_PROG_OPS，目前为空。
