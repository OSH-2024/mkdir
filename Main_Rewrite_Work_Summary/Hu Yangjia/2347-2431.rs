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
