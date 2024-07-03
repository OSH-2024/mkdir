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