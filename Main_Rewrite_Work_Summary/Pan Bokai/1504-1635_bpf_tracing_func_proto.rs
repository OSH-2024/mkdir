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
        bpf_func_id::BPF_FUNC_trace_vprintk => bpf_get_trace_vprintk_proto(),
        _ => bpf_base_func_proto(func_id),
    }
}