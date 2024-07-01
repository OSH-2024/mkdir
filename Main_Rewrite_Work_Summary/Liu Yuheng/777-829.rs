let bpf_get_current_task_btf_proto = bpf_func_proto {
    func: bpf_get_current_task_btf,
    gpl_only: true,
    ret_type: RET_PTR_TO_BTF_ID_TRUSTED,
    ret_btf_id: &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
};
fn bpf_task_pt_regs(task : NonNull<task_struct>)-> u64{
    let ret = task_pt_regs(task) as u64;
    ret
}
BTF_ID_LIST(bpf_task_pt_regs_ids)
BTF_ID(struct, pt_regs)
let bpf_task_pt_regs_proto = bpf_func_proto {
    func: bpf_task_pt_regs,
    gpl_only: true,
    arg1_type	: ARG_PTR_TO_BTF_ID,
	arg1_btf_id	: &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	ret_type	: RET_PTR_TO_BTF_ID,
	ret_btf_id	: &bpf_task_pt_regs_ids[0],
}

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

let  bpf_current_task_under_cgroup_proto = bpf_func_proto{
	func           : bpf_current_task_under_cgroup,
	gpl_only       : false,
	ret_type       : RET_INTEGER,
	arg1_type      : ARG_CONST_MAP_PTR,
	arg2_type      : ARG_ANYTHING,
};
struct send_signal_irq_work {
	irq_work:irq_work ;
    task: NonNull<	task_struct >;
	sig:u32;
	type: pid_type;
};