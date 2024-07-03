
// 1720-1732
unsafe fn bpf_get_stackid_tp(tp_buff: *mut c_void, map: *mut BpfMap, flags: u64) -> i32 {
    // 将`tp_buff`转换为`*mut *mut pt_regs`类型的裸指针
    let regs = *(tp_buff as *mut *mut pt_regs);

    // 调用外部C函数`bpf_get_stackid`
    // 注意：这里需要将`regs`和`map`转换为`u64`，因为外部函数期望的是无符号长整型
    // `0, 0`为额外的参数，根据实际情况调整
    bpf_get_stackid(regs as u64, map as u64, flags, 0, 0)
}

// 1733-1742 TODO:
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

// 1743-1750
unsafe fn bpf_get_stack_tp(tp_buff: *mut c_void, buf: *mut c_void, size: u32, flags: u64) -> i32 {
    // 将`tp_buff`转换为`*mut *mut pt_regs`类型的裸指针
    let regs = *(tp_buff as *mut *mut pt_regs);

    // 调用外部C函数`bpf_get_stack`
    // 注意：这里需要将`regs`、`buf`和`size`转换为`u64`，因为外部函数期望的是无符号长整型
    // `0`为额外的参数，根据实际情况调整
    bpf_get_stack(regs as u64, buf as u64, size as u64, flags, 0)
}

// 1751-1778 TODO:
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

// 1779-1792
static bool tp_prog_is_valid_access(int off, int size, enum bpf_access_type type,
    const struct bpf_prog *prog,
    struct bpf_insn_access_aux *info)
{
    if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
        return false;
    if (type != BPF_READ)
        return false;
    if (off % size != 0)
        return false;

    BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(__u64));
    return true;
}

// Compare this snippet from mkdir/Main_Rewrite_Work_Summary/Hu%20Yangjia/tp_prog_is_valid_access.rs:
pub fn tp_prog_is_valid_access(off: i32, size: i32, type_: bpf_access_type, 
    prog: *const bpf_prog, info: *mut bpf_insn_access_aux) -> bool {
    if off < std::mem::size_of::<*const std::ffi::c_void>() as i32 || off >= PERF_MAX_TRACE_SIZE as i32 
    {
        return false;
    }
    if type_ != BPF_READ {
        return false;
    }
    if off % size != 0 {
        return false;
    }

    BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % std::mem::size_of::<u64>() as i32);
    return true;
}

// 1793-1801 TODO:
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

// 1802-1817
unsafe fn bpf_perf_prog_read_value(
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

// 1818-1827 TODO:
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

// 1828-1855
// BPF_CALL_4 宏的 Rust 实现
macro_rules! BPF_CALL_4 {
    ($func:ident, $($arg:ty),+) => {
        #[no_mangle]
        pub unsafe extern "C" fn $func(ctx: *mut bpf_perf_event_data_kern, buf: *mut u8, size: u32, flags: u64) -> i32 {
            // 定义常量 br_entry_size,表示 perf_branch_entry 结构体的大小
            const BR_ENTRY_SIZE: u32 = std::mem::size_of::<perf_branch_entry>() as u32;

            // 检查 flags 参数是否合法
            if unlikely((flags & !BPF_F_GET_BRANCH_RECORDS_SIZE) != 0) {
                return -EINVAL;
            }

            // 获取 ctx->data->br_stack 指针
            let br_stack = (*ctx).data.as_ref().and_then(|data| data.br_stack.as_ref());

            // 如果 ctx->data->sample_flags 不包含 PERF_SAMPLE_BRANCH_STACK 标志,则返回 -ENOENT
            if unlikely(!((*ctx).data.as_ref().map_or(false, |data| data.sample_flags & PERF_SAMPLE_BRANCH_STACK != 0))) {
                return -ENOENT;
            }

            // 如果 br_stack 为 null,则返回 -ENOENT
            if unlikely(br_stack.is_none()) {
                return -ENOENT;
            }

            // 如果 flags 包含 BPF_F_GET_BRANCH_RECORDS_SIZE 标志,则返回 br_stack 中条目的总大小
            if flags & BPF_F_GET_BRANCH_RECORDS_SIZE != 0 {
                return (br_stack.unwrap().nr * BR_ENTRY_SIZE) as i32;
            }

            // 检查 buf 和 size 参数是否合法
            if buf.is_null() || (size % BR_ENTRY_SIZE != 0) {
                return -EINVAL;
            }

            // 计算需要复制的数据大小
            let to_copy = std::cmp::min(br_stack.unwrap().nr * BR_ENTRY_SIZE, size);

            // 将 br_stack 中的条目复制到 buf 中
            std::ptr::copy_nonoverlapping(br_stack.unwrap().entries.as_ptr(), buf, to_copy as usize);

            // 返回复制的数据大小
            to_copy as i32
        }
    };
}

// 使用 BPF_CALL_4 宏定义 bpf_read_branch_records 函数
BPF_CALL_4!(bpf_read_branch_records, *mut bpf_perf_event_data_kern, *mut u8, u32, u64);

// 1856-1886
// 定义 bpf_read_branch_records_proto 常量
const BPF_READ_BRANCH_RECORDS_PROTO: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_read_branch_records),
    gpl_only: true,
    ret_type: RET_INTEGER,
    arg1_type: ARG_PTR_TO_CTX,
    arg2_type: ARG_PTR_TO_MEM_OR_NULL,
    arg3_type: ARG_CONST_SIZE_OR_ZERO,
    arg4_type: ARG_ANYTHING,
};

// pe_prog_func_proto 函数
pub fn pe_prog_func_proto(func_id: bpf_func_id, prog: *const bpf_prog) -> *const bpf_func_proto {
    match func_id {
        BPF_FUNC_perf_event_output => &bpf_perf_event_output_proto_tp,
        BPF_FUNC_get_stackid => &bpf_get_stackid_proto_pe,
        BPF_FUNC_get_stack => &bpf_get_stack_proto_pe,
        BPF_FUNC_perf_prog_read_value => &bpf_perf_prog_read_value_proto,
        BPF_FUNC_read_branch_records => &BPF_READ_BRANCH_RECORDS_PROTO,
        BPF_FUNC_get_attach_cookie => &bpf_get_attach_cookie_proto_pe,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}

// 1887-1991
struct  bpf_raw_tp_regs{
    regs: [pt_regs; 3],
}
unsafe{
    bindings::DEFINE_PER_CPU(struct bpf_raw_tp_regs, bpf_raw_tp_regs);
    bindings::DEFINE_PER_CPU(int, bpf_raw_tp_nest_level);
}
fn get_bpf_raw_tp_regs()->*mut bpf_raw_tp_regs{
    unsafe{
        let mut tp_regs:NonNull<bpf_raw_tp_regs> = bindings::this_cpu_ptr(&bpf_raw_tp_regs);
        let mut nest_level:i32 = bindings::this_cpu_read(&bpf_raw_tp_nest_level);
        if bindings::WARN_ON_ONCE(nest_level > bindings::ARRAY_SIZE(*(tp_regs.as_ptr()).regs)){
            bindings::this_cpu_dec(bpf_raw_tp_nest_level);
            return ERR_PTR(-EBUSY);
        }
        let regs_ptr: *mut PtRegs = (*tp_regs.as_ptr()).regs.as_mut_ptr().add(nest_level as usize - 1);
        Ok(regs_ptr)
    }
}
fn put_bpf_raw_tp_regs{
    unsafe{
        bindings::this_cpu_dec(bpf_raw_tp_nest_level);
    }
}
fn bpf_perf_event_output_raw_tp(args:NonNull<bpf_raw_tracepoint_args>,map:NonNull<bpf_map>,flags:u64,data:NonNull<c_void>,size:u64)->i32{
    unsafe{
        let mut regs : *mut pt_regs = get_bpf_raw_tp_regs();
        if IS_ERR(regs){
            return PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::____bpf_perf_event_output(regs, map, flags, data, size);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}
let  bpf_perf_event_output_proto_raw_tp = bpf_func_proto{
	func		: bpf_perf_event_output_raw_tp,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_CONST_MAP_PTR,
	arg3_type	: ARG_ANYTHING,
	arg4_type	: ARG_PTR_TO_MEM | MEM_RDONLY,
	arg5_type	: ARG_CONST_SIZE_OR_ZERO,
};
extern "C" {
    static bpf_skb_output_proto: bpf_func_proto;
    static bpf_xdp_output_proto: bpf_func_proto;
    static bpf_xdp_get_buff_len_trace_proto;
}
fn bpf_get_stackid_raw_tp(args:NonNull<bpf_raw_tracepoint_args>,map:NonNull<bpf_map>,flags:u64){
    unsafe{
        let mut regs : *mut pt_regs = get_bpf_raw_tp_regs();
        if IS_ERR(regs){
            return PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::bpf_get_stackid( regs as u64,  map as u64,flags, 0, 0);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}
let  bpf_get_stackid_proto_raw_tp = bpf_func_proto{
	func		: bpf_get_stackid_raw_tp,
	gpl_only	: true,
	ret_type	: RET_INTEGER,
	arg1_type	: ARG_PTR_TO_CTX,
	arg2_type	: ARG_CONST_MAP_PTR,
	arg3_type	: ARG_ANYTHING,
};
fn bpf_get_stack_raw_tp(args : NonNull<bpf_raw_tracepoint_args>,buf:NonNull<c_void>,size:u32,flags:u64){
    unsafe{
        let mut regs : *mut pt_regs = bindings::get_bpf_raw_tp_regs();
        if bindings::IS_ERR(regs){
            return bindings::PTR_ERR(regs);
        }
        bindings::perf_fetch_caller_regs(regs);
        let mut ret = bindings::bpf_get_stack( regs as u64,  buf as u64, size, flags,0);
        bindings::put_bpf_raw_tp_regs();
        ret
    }
}

// 1992-2015
// 定义 bpf_get_stack_proto_raw_tp 常量
const BPF_GET_STACK_PROTO_RAW_TP: bpf_func_proto = bpf_func_proto {
    func: Some(bpf_get_stack_raw_tp),
    gpl_only: true,
    ret_type: RET_INTEGER,
    arg1_type: ARG_PTR_TO_CTX,
    arg2_type: ARG_PTR_TO_MEM | MEM_RDONLY,
    arg3_type: ARG_CONST_SIZE_OR_ZERO,
    arg4_type: ARG_ANYTHING,
};

// raw_tp_prog_func_proto 函数
pub fn raw_tp_prog_func_proto(func_id: bpf_func_id, prog: *const bpf_prog) -> *const bpf_func_proto {
    match func_id {
        BPF_FUNC_perf_event_output => &bpf_perf_event_output_proto_raw_tp,
        BPF_FUNC_get_stackid => &bpf_get_stackid_proto_raw_tp,
        BPF_FUNC_get_stack => &BPF_GET_STACK_PROTO_RAW_TP,
        _ => bpf_tracing_func_proto(func_id, prog),
    }
}

// 2016-2081

#[cfg(feature = CONFIG_NET)]
fn tracing_prog_func_proto(func_id: bpf_func_id, prog: *mut bpf_prog )-> *mut bpf_func_proto
{
    let fn: *mut bpf_func_proto;
    match (func_id)
    {
        BPF_FUNC_skb_output => return &bpf_skb_output_proto,
        BPF_FUNC_xdp_output => return &bpf_xdp_output_proto,
        BPF_FUNC_skc_to_tcp6_sock => return &bpf_skc_to_tcp6_sock_proto,
        BPF_FUNC_skc_to_tcp_sock => return &bpf_skc_to_tcp_sock_proto,
        BPF_FUNC_skc_to_tcp_timewait_sock => return &bpf_skc_to_tcp_timewait_sock_proto,
        BPF_FUNC_skc_to_tcp_request_sock => return &bpf_skc_to_tcp_request_sock_proto,
        BPF_FUNC_skc_to_udp6_sock => return &bpf_skc_to_udp6_sock_proto,
        BPF_FUNC_skc_to_unix_sock => return &bpf_skc_to_unix_sock_proto,
        BPF_FUNC_skc_to_mptcp_sock => return &bpf_skc_to_mptcp_sock_proto,
        BPF_FUNC_sk_storage_get => return &bpf_sk_storage_get_tracing_proto,
        BPF_FUNC_sk_storage_delete => return &bpf_sk_storage_delete_tracing_proto,
        BPF_FUNC_sock_from_file => return &bpf_sock_from_file_proto,
        BPF_FUNC_get_socket_cookie => return &bpf_get_socket_ptr_cookie_proto,
        BPF_FUNC_xdp_get_buff_len => return &bpf_xdp_get_buff_len_trace_proto,
        BPF_FUNC_seq_printf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_proto : NULL,
        BPF_FUNC_seq_write => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_write_proto : NULL,
        BPF_FUNC_seq_printf_btf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_btf_proto : NULL,
        BPF_FUNC_d_path => return &bpf_d_path_proto,
        BPF_FUNC_get_func_arg => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_proto : NULL,
        BPF_FUNC_get_func_ret => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_ret_proto : NULL,
        BPF_FUNC_get_func_arg_cnt => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_cnt_proto : NULL,
        BPF_FUNC_get_attach_cookie => return bpf_prog_has_trampoline(prog) ? &bpf_get_attach_cookie_proto_tracing : NULL,
        _ => {
            fn = raw_tp_prog_func_proto(func_id, prog);
            if !fn && prog->expected_attach_type == BPF_TRACE_ITER
            {
                fn = bpf_iter_get_func_proto(func_id, prog);
            }
            return fn;
        }

    }
}

#[cfg(not(feature = CONFIG_NET))]
fn tracing_prog_func_proto(func_id: bpf_func_id, prog: *mut bpf_prog )-> *mut bpf_func_proto
{
    let fn: *mut bpf_func_proto;
    match (func_id)
    {
        BPF_FUNC_seq_printf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_proto : NULL,
        BPF_FUNC_seq_write => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_write_proto : NULL,
        BPF_FUNC_seq_printf_btf => return prog->expected_attach_type == BPF_TRACE_ITER ? &bpf_seq_printf_btf_proto : NULL,
        BPF_FUNC_d_path => return &bpf_d_path_proto,
        BPF_FUNC_get_func_arg => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_proto : NULL,
        BPF_FUNC_get_func_ret => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_ret_proto : NULL,
        BPF_FUNC_get_func_arg_cnt => return bpf_prog_has_trampoline(prog) ? &bpf_get_func_arg_cnt_proto : NULL,
        BPF_FUNC_get_attach_cookie => return bpf_prog_has_trampoline(prog) ? &bpf_get_attach_cookie_proto_tracing : NULL,
        _ => {
            fn = raw_tp_prog_func_proto(func_id, prog);
            if !fn && prog->expected_attach_type == BPF_TRACE_ITER
            {
                fn = bpf_iter_get_func_proto(func_id, prog);
            }
            return fn;
        }

    }
}

// 2082-2089
// raw_tp_prog_is_valid_access 函数的 Rust 实现
fn raw_tp_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 调用 bpf_tracing_ctx_access 函数,传入偏移量、大小和访问类型
    // 返回访问是否有效
    bpf_tracing_ctx_access(off, size, access_type)
}

// 2090-2097
// tracing_prog_is_valid_access 函数的 Rust 实现
fn tracing_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 调用 bpf_tracing_btf_ctx_access 函数,传入偏移量、大小、访问类型、BPF 程序和访问信息
    // 返回访问是否有效
    bpf_tracing_btf_ctx_access(off, size, access_type, prog, info)
}

// 2098-2124
#[no_mangle] // 确保函数名在编译后不会被改变，以便C代码可以找到它
pub extern "C" fn bpf_prog_test_run_tracing(prog: *const c_void, kattr: *const c_void, uattr: *mut c_void) -> c_int {
    // 返回-ENOTSUPP错误码，表示不支持的操作
    // 假设-ENOTSUPP为-95，实际值应根据具体环境确定
    -95
}

// 定义Rust版本的`bpf_verifier_ops`和`bpf_prog_ops`结构体
#[repr(C)]
struct bpf_verifier_ops {
    get_func_proto: extern "C" fn() -> *const c_void,
    is_valid_access: extern "C" fn() -> c_int,
}

#[repr(C)]
struct bpf_prog_ops {
    // 使用`Option`来处理可能不存在的函数指针
    test_run: Option<extern "C" fn(prog: *const c_void, kattr: *const c_void, uattr: *mut c_void) -> c_int>,
}

// 实例化`bpf_verifier_ops`和`bpf_prog_ops`结构体
static RAW_TRACEPOINT_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    get_func_proto: raw_tp_prog_func_proto,
    is_valid_access: raw_tp_prog_is_valid_access,
};

static RAW_TRACEPOINT_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
    // 使用条件编译来处理可选的函数指针
    #[cfg(feature = "config_net")]
    test_run: Some(bpf_prog_test_run_raw_tp),
    #[cfg(not(feature = "config_net"))]
    test_run: None,
};

static TRACING_VERIFIER_OPS: bpf_verifier_ops = bpf_verifier_ops {
    get_func_proto: tracing_prog_func_proto,
    is_valid_access: tracing_prog_is_valid_access,
};

static TRACING_PROG_OPS: bpf_prog_ops = bpf_prog_ops {
    test_run: Some(bpf_prog_test_run_tracing),
};

// 2125-2137
// raw_tp_writable_prog_is_valid_access 函数的 Rust 实现
fn raw_tp_writable_prog_is_valid_access(
    off: i32,
    size: i32,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    if off == 0 {
        // 如果偏移量为0
        if size != std::mem::size_of::<u64>() as i32 || access_type != bpf_access_type::BPF_READ {
            // 如果大小不等于 u64 的大小或访问类型不是读,返回 false
            return false;
        }
        // 将 info 的 reg_type 字段设置为 PTR_TO_TP_BUFFER
        info.reg_type = bpf_reg_type::PTR_TO_TP_BUFFER;
    }
    // 调用 raw_tp_prog_is_valid_access 函数,传入偏移量、大小、访问类型、BPF 程序和访问信息
    // 返回访问是否有效
    raw_tp_prog_is_valid_access(off, size, access_type, prog, info)
}

// 2138-2145
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

// 2146-2183
// pe_prog_is_valid_access 函数的 Rust 实现
fn pe_prog_is_valid_access(
    off: i32,
    size: usize,
    access_type: bpf_access_type,
    prog: &bpf_prog,
    info: &mut bpf_insn_access_aux,
) -> bool {
    // 定义 u64 的大小
    let size_u64 = std::mem::size_of::<u64>() as i32;

    // 如果偏移量小于0或大于 bpf_perf_event_data 结构体的大小,返回 false
    if off < 0 || off >= std::mem::size_of::<bpf_perf_event_data>() as i32 {
        return false;
    }
    // 如果访问类型不是读,返回 false
    if access_type != bpf_access_type::BPF_READ {
        return false;
    }
    // 如果偏移量不是大小的整数倍
    if off % size as i32 != 0 {
        // 如果 unsigned long 不是 4 字节,返回 false
        if std::mem::size_of::<usize>() as i32 != 4 {
            return false;
        }
        // 如果大小不是 8 字节,返回 false
        if size != 8 {
            return false;
        }
        // 如果偏移量不是 4 的倍数,返回 false
        if off % 4 != 0 {
            return false;
        }
    }

    // 根据偏移量进行不同的处理
    match off {
        // bpf_perf_event_data 结构体的 sample_period 字段
        bpf_ctx_range!(bpf_perf_event_data, sample_period) => {
            // 记录字段大小为 u64
            bpf_ctx_record_field_size(info, size_u64);
            // 检查访问是否合法
            if !bpf_ctx_narrow_access_ok(off, size as i32, size_u64) {
                return false;
            }
        }
        // bpf_perf_event_data 结构体的 addr 字段
        bpf_ctx_range!(bpf_perf_event_data, addr) => {
            // 记录字段大小为 u64
            bpf_ctx_record_field_size(info, size_u64);
            // 检查访问是否合法
            if !bpf_ctx_narrow_access_ok(off, size as i32, size_u64) {
                return false;
            }
        }
        // 其他字段
        _ => {
            // 如果大小不是 long 的大小,返回 false
            if size != std::mem::size_of::<usize>() {
                return false;
            }
        }
    }

    // 访问合法
    true
}

// 2184-2232
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

let perf_event_verifier_ops: bpf_verifier_ops = bpf_verifier_ops 
{
    get_func_proto = pe_prog_func_proto,
    is_valid_access = pe_prog_is_valid_access,
    convert_ctx_access = pe_prog_convert_ctx_access
}


"
const struct bpf_prog_ops perf_event_prog_ops = {
};

static DEFINE_MUTEX(bpf_event_mutex);

#define BPF_TRACE_MAX_PROGS 64
"TODO:

// 2233-2346
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

// 2347-2431
extern "C" {
    static __start__bpf_raw_tp: [bpf_raw_event_map; 0];
    static __stop__bpf_raw_tp: [bpf_raw_event_map; 0];
}
use std::ffi::c_char;
use std::os::raw::c_ulong;


fn bpf_get_raw_tracepoint(name: *const c_char) -> *mut bpf_raw_event_map 
{
    let mut btp: *mut bpf_raw_event_map = __start__bpf_raw_tp;
    while btp < __stop__bpf_raw_tp 
    {
        if strcmp(btp.tp.name, name) == 0 
        {
            return btp;
        }
        btp = btp.offset(1);
    }
    return bpf_get_raw_tracepoint_module(name);
}

fn bpf_put_raw_tracepoint(btp: *mut bpf_raw_event_map) 
{
    let mod: *mut module;
    preempt_disable();
    mod = __module_address(btp as c_ulong);
    module_put(mod);
    preempt_enable();
}

fn __bpf_trace_run(prog: *mut bpf_prog, args: *mut c_ulong) 
{
'out' loop {
    cant_sleep();
    if (this_cpu_inc_return(*prog.active) != 1) 
    {
        bpf_prog_inc_misses_counter(prog);
        break 'out';
    }
    rcu_read_lock();
    bpf_prog_run(prog, args);
    rcu_read_unlock();
}
    this_cpu_dec(*prog.active);
}


#define UNPACK(...)			__VA_ARGS__
#define REPEAT_1(FN, DL, X, ...)	FN(X)
#define REPEAT_2(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_1(FN, DL, __VA_ARGS__)
#define REPEAT_3(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_2(FN, DL, __VA_ARGS__)
#define REPEAT_4(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_3(FN, DL, __VA_ARGS__)
#define REPEAT_5(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_4(FN, DL, __VA_ARGS__)
#define REPEAT_6(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_5(FN, DL, __VA_ARGS__)
#define REPEAT_7(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_6(FN, DL, __VA_ARGS__)
#define REPEAT_8(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_7(FN, DL, __VA_ARGS__)
#define REPEAT_9(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_8(FN, DL, __VA_ARGS__)
#define REPEAT_10(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_9(FN, DL, __VA_ARGS__)
#define REPEAT_11(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_10(FN, DL, __VA_ARGS__)
#define REPEAT_12(FN, DL, X, ...)	FN(X) UNPACK DL REPEAT_11(FN, DL, __VA_ARGS__)
#define REPEAT(X, FN, DL, ...)		REPEAT_##X(FN, DL, __VA_ARGS__)

#define SARG(X)		u64 arg##X
#define COPY(X)		args[X] = arg##X

#define __DL_COM	(,)
#define __DL_SEM	(;)

#define __SEQ_0_11	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11

#define BPF_TRACE_DEFN_x(x)						\
	void bpf_trace_run##x(struct bpf_prog *prog,			\
			      REPEAT(x, SARG, __DL_COM, __SEQ_0_11))	\
	{								\
		u64 args[x];						\
		REPEAT(x, COPY, __DL_SEM, __SEQ_0_11);			\
		__bpf_trace_run(prog, args);				\
	}								\
	EXPORT_SYMBOL_GPL(bpf_trace_run##x)
BPF_TRACE_DEFN_x(1);
BPF_TRACE_DEFN_x(2);
BPF_TRACE_DEFN_x(3);
BPF_TRACE_DEFN_x(4);
BPF_TRACE_DEFN_x(5);
BPF_TRACE_DEFN_x(6);
BPF_TRACE_DEFN_x(7);
BPF_TRACE_DEFN_x(8);
BPF_TRACE_DEFN_x(9);
BPF_TRACE_DEFN_x(10);
BPF_TRACE_DEFN_x(11);
BPF_TRACE_DEFN_x(12);

// 2432-2577

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

// 2578-2602

#[cfg(feature = CONFIG_FPROBE)]

struct bpf_kprobe_multi_link
{
    link: bpf_link,
    fp: fprobe,
    addrs: *mut c_ulong,
    cookies: *mut u64,
    cnt: u32,
    mods_cnt: u32,
    mods: *mut *mut module,
    flags: u32
}

struct bpf_kprobe_multi_run_ctx
{
    run_ctx: bpf_run_ctx,
    link: *mut bpf_kprobe_multi_link,
    entry_ip: c_ulong
}

struct user_syms
{
    syms: *mut *mut c_char,
    buf: *mut c_char
}

// 2603-2769
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

// 2770-2843
fn bpf_kprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    let run_ctx: *mut bpf_kprobe_multi_run_ctx = container_of((*ctx).bpf_ctx, bpf_kprobe_multi_run_ctx, run_ctx);
    return (*run_ctx).entry_ip;
}

fn kprobe_multi_link_prog_run(link: *mut bpf_kprobe_multi_link, entry_ip: c_ulong, regs: *mut pt_regs) -> i32
{
    let run_ctx: bpf_kprobe_multi_run_ctx = {
        .link = link,
        .entry_ip = entry_ip,
    };
    let old_run_ctx: *mut bpf_run_ctx;
    let err: i32;

'out' : loop {
    if((__this_cpu_inc_return(bpf_prog_active) != 1))
    {
        bpf_prog_inc_misses_counter((*link).link.prog);
        err = 0;
        break 'out';
    }

    migrate_disable();
    rcu_read_lock();
    old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
    err = bpf_prog_run((*link).link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);
    rcu_read_unlock();
    migrate_enable();
}
    
    __this_cpu_dec(bpf_prog_active);
    return err;
}

static int
kprobe_multi_link_prog_run(struct bpf_kprobe_multi_link *link,
			   unsigned long entry_ip, struct pt_regs *regs)
{
	struct bpf_kprobe_multi_run_ctx run_ctx = {
		.link = link,
		.entry_ip = entry_ip,
	};
	struct bpf_run_ctx *old_run_ctx;
	int err;

	if (unlikely(__this_cpu_inc_return(bpf_prog_active) != 1)) {
		bpf_prog_inc_misses_counter(link->link.prog);
		err = 0;
		goto out;
	}

	migrate_disable();
	rcu_read_lock();
	old_run_ctx = bpf_set_run_ctx(&run_ctx.run_ctx);
	err = bpf_prog_run(link->link.prog, regs);
	bpf_reset_run_ctx(old_run_ctx);
	rcu_read_unlock();
	migrate_enable();

 out:
	__this_cpu_dec(bpf_prog_active);
	return err;
}

fn kprobe_multi_link_handler(fp: *mut fprobe, fentry_ip: c_ulong, ret_ip: c_ulong, regs: *mut pt_regs, data: *mut c_void) -> i32
{
    let link: *mut bpf_kprobe_multi_link;

    link = container_of(fp, bpf_kprobe_multi_link, fp);
    kprobe_multi_link_prog_run(link, get_entry_ip(fentry_ip), regs);
    return 0;
}

fn kprobe_multi_link_exit_handler(fp: *mut fprobe, fentry_ip: c_ulong, ret_ip: c_ulong, regs: *mut pt_regs, data: *mut c_void)
{
    let link: *mut bpf_kprobe_multi_link;

    link = container_of(fp, bpf_kprobe_multi_link, fp);
    kprobe_multi_link_prog_run(link, get_entry_ip(fentry_ip), regs);
}

fn symbols_cmp_r(a: *const *const c_char, b: *const *const c_char, priv: *const c_void) -> i32
{
    let str_a: *const *const c_char = a;
    let str_b: *const *const c_char = b;

    return strcmp(*str_a, *str_b);
}

struct multi_symbols_sort
{
    funcs: *mut *mut c_char,
    cookies: *mut u64
}

// 2844-2860
// symbols_swap_r 函数的 Rust 实现
fn symbols_swap_r(a: *mut c_void, b: *mut c_void, size: i32, priv_data: *const c_void) {
    // 将 priv_data 转换为 multi_symbols_sort 结构体的不可变引用
    let data = unsafe { &*(priv_data as *const multi_symbols_sort) };

    // 将 a 和 b 转换为可变的字符串切片引用
    let name_a = unsafe { &mut *(a as *mut &str) };
    let name_b = unsafe { &mut *(b as *mut &str) };

    // 交换 name_a 和 name_b 的值
    std::mem::swap(name_a, name_b);

    // 如果定义了 cookies,则同时交换相关的 cookies
    if let Some(cookies) = data.cookies {
        // 计算 cookie_a 和 cookie_b 的位置
        let cookie_a = unsafe { cookies.offset((name_a as *const _ as usize - data.funcs as usize) as isize) };
        let cookie_b = unsafe { cookies.offset((name_b as *const _ as usize - data.funcs as usize) as isize) };

        // 交换 cookie_a 和 cookie_b 的值
        let cookie_a = unsafe { &mut *cookie_a };
        let cookie_b = unsafe { &mut *cookie_b };
        std::mem::swap(cookie_a, cookie_b);
    }
}

// 2861-2883
struct modules_array
{
    mods: *mut *mut module,
    mods_cnt: i32,
    mods_cap: i32
}

fn add_module(arr: *mut modules_array, mod: *mut module) -> i32
{
    let mods: *mut *mut module;
    if (*arr).mods_cnt == (*arr).mods_cap
    {
        (*arr).mods_cap = max(16, (*arr).mods_cap * 3 / 2);
        mods = krealloc_array((*arr).mods, (*arr).mods_cap, mem::size_of::<*mut module>(), GFP_KERNEL);
        if mods.is_null()
        {
            return -ENOMEM;
        }
        (*arr).mods = mods;
    }
    (*arr).mods[(*arr).mods_cnt as usize] = mod;
    (*arr).mods_cnt += 1;
    return 0;
}

// 2884-2894
// has_module 函数的 Rust 实现
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

// 2895-2933
// get_modules_for_addrs 函数的 Rust 实现
fn get_modules_for_addrs(addrs: &[u64]) -> Result<Vec<&module>, i32> {
    let mut arr = modules_array::default();
    let mut err = 0;

    // 遍历给定的地址数组
    for addr in addrs {
        // 禁用抢占
        preempt_disable();
        // 根据地址获取对应的模块
        let module = unsafe { __module_address(*addr) };
        // 如果模块不存在或已经存储,启用抢占并继续下一个地址
        if module.is_null() || has_module(&arr, module) {
            preempt_enable();
            continue;
        }
        // 尝试获取模块引用计数
        if !try_module_get(module) {
            err = -EINVAL;
        }
        // 启用抢占
        preempt_enable();
        // 如果出错,跳出循环
        if err != 0 {
            break;
        }
        // 将模块添加到数组中
        err = add_module(&mut arr, module);
        if err != 0 {
            // 如果添加失败,释放模块引用计数并跳出循环
            module_put(module);
            break;
        }
    }

    // 如果出错,释放数组中的模块并返回错误码
    if err != 0 {
        kprobe_multi_put_modules(&arr.mods, arr.mods_cnt);
        return Err(err);
    }

    // 如果一切正常,返回找到的模块数组
    Ok(arr.mods)
}

// 2934-2944
// addrs_check_error_injection_list 函数的 Rust 实现
fn addrs_check_error_injection_list(addrs: &[u64]) -> Result<(), i32> {
    // 遍历给定的地址数组
    for addr in addrs {
        // 检查地址是否在错误注入列表中
        if !within_error_injection_list(*addr) {
            // 如果有任何地址不在错误注入列表中,返回错误码 -EINVAL
            return Err(-EINVAL);
        }
    }
    // 如果所有地址都在错误注入列表中,返回 Ok(())
    Ok(())
}

// 2945-3086
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

// 3087-3158

#[cfg(not(feature = CONFIG_FPROBE))]

fn bpf_kprobe_multi_link_attach(attr: *union bpf_attr, prog: *mut bpf_prog) -> i32 
{
    return -EOPNOTSUPP;
}

fn  bpf_kprobe_multi_cookie(ctx: *mut bpf_run_ctx) -> u64
{
    return 0;
}

fn bpf_kprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    return 0;
}


#[cfg(feature = CONFIG_UPROBES)]
struct bpf_uprobe_multi_link;

struct bpf_uprobe 
{
    link: *mut bpf_uprobe_multi_link,
    offset: loff_t,
    ref_ctr_offset: c_ulong,
    cookie: u64,
    consumer: uprobe_consumer
}

struct bpf_uprobe_multi_link 
{
    path: path,
    link: bpf_link,
    cnt: u32,
    flags: u32,
    uprobes: *mut bpf_uprobe,
    task: *mut task_struct
}

struct bpf_uprobe_multi_run_ctx 
{
    run_ctx: bpf_run_ctx,
    entry_ip: c_ulong,
    uprobe: *mut bpf_uprobe
}

fn bpf_uprobe_unregister(path: *mut path, uprobes: *mut bpf_uprobe, cnt: u32)
{
    let mut i: u32 = 0;
    while i < cnt 
    {
        uprobe_unregister(d_real_inode(path.dentry), uprobes[i].offset, &uprobes[i].consumer);
        i += 1;
    }
}

fn bpf_uprobe_multi_link_release(link: *mut bpf_link)
{
    let umulti_link: *mut bpf_uprobe_multi_link = container_of(link, struct bpf_uprobe_multi_link, link);
    bpf_uprobe_unregister(&umulti_link.path, umulti_link.uprobes, umulti_link.cnt);
}

fn bpf_uprobe_multi_link_dealloc(link: *mut bpf_link)
{
    let umulti_link: *mut bpf_uprobe_multi_link = container_of(link, struct bpf_uprobe_multi_link, link);
    if umulti_link.task != 0
    {
        put_task_struct(umulti_link.task);
    }
    path_put(&umulti_link.path);
    kvfree(umulti_link.uprobes);
    kfree(umulti_link);
}

// 3159-3227
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

// 3228-3314

// 全局变量，使用 lazy_static 宏和 Mutex 来保证线程安全
lazy_static! 
{
    static ref bpf_uprobe_multi_link_lops: Mutex<bpf_link_ops> = Mutex::new(bpf_link_ops 
    {
        release: bpf_uprobe_multi_link_release,
        dealloc: bpf_uprobe_multi_link_dealloc,
        fill_link_info: bpf_uprobe_multi_link_fill_link_info,
    });
}

fn uprobe_prog_run(*mut uprobe: *mut bpf_uprobe,
                    entry_ip: c_ulong,
                   *mut regs: *mut pt_regs) -> i32
{
    let mut link: *mut bpf_uprobe_multi_link = (*uprobe).link;
    let mut run_ctx:  bpf_uprobe_multi_run_ctx = bpf_uprobe_multi_run_ctx
    {
        entry_ip: entry_ip,
        uprobe: uprobe,
    };
    let mut prog: *mut bpf_prog = link.link.prog;
    let mut sleepable: bool = prog.aux.sleepable;
    let mut old_run_ctx:Box<bpf_run_ctx> = Box::new(bpf_run_ctx::new());
    let mux err: i32 = 0;

    if(link.task && current != link.task)
    {
        return 0;
    }
    if(sleepable)
    {
        rcu_read_lock_trace();
    }
    else
    {
        rcu_read_lock();
    }
    migrate_disable();

    old_run_ctx = bpf_set_run_ctx(run_ctx.run_ctx);
    err = bpf_prog_run(link.link.prog, regs);
    bpf_reset_run_ctx(old_run_ctx);

    migrate_enable();

    if(sleepable)
    {
        rcu_read_unlock_trace();
    }
    else
    {
        rcu_read_unlock();
    }
    return err;
}

fn uprobe_multi_link_filter(con: *mut uprobe_consumer, ctx: enum uprobe_filter_ctx, mm: *mut mm_struct) -> bool
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe.link.task.mm == mm;
}

fn uprobe_multi_link_handler(con: *mut uprobe_consumer, regs: *mut pt_regs) -> i32
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, instruction_pointer(regs), regs);
}


fn uprobe_multi_link_ret_handler(con: *mut uprobe_consumer, func: c_ulong, regs: *mut pt_regs) -> i32
{
    let mut uprobe: Box<bpf_uprobe> = Box::new(bpf_uprobe::new());
    uprobe = container_of(con, bpf_uprobe, consumer);
    return uprobe_prog_run(uprobe, func, regs);
}

fn bpf_uprobe_multi_entry_ip(ctx: *mut bpf_run_ctx) -> u64
{
    let mut run_ctx: *mut bpf_uprobe_multi_run_ctx = container_of(current.bpf_ctx, bpf_uprobe_multi_run_ctx, run_ctx);
    return run_ctx.entry_ip;
}

fn bpf_uprobe_multi_cookie(ctx: *mut bpf_run_ctx) -> u64
{
    let mut run_ctx: *mut bpf_uprobe_multi_run_ctx = container_of(current.bpf_ctx, bpf_uprobe_multi_run_ctx, run_ctx);
    return run_ctx.uprobe.cookie;
}


// 3315-3456

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

// 3458-3469
#[cfg(not(feature = CONFIG_UPROBES))]
fn bpf_uprobe_multi_link_attach(attr: &bpf_attr, prog: &bpf_prog) -> i32 {
    return -EOPNOTSUPP;
}   

fn bpf_uprobe_multi_cookie(ctx: &bpf_run_ctx) -> u64 {
    return 0;
}

fn bpf_uprobe_multi_entry_ip(ctx: &bpf_run_ctx) -> u64 {
    return 0;
}   
