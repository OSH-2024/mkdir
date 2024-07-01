use std::ffi::c_void;
use std::ptr::NonNull;
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
let bpf_probe_write_user_proto = BpfFuncProto {
    func: bpf_probe_write_user, // 假设 bpf_probe_read_user 是已经定义的 Rust 函数
    gpl_only: true,
    ret_type: RetType::RET_INTEGER,
    arg1_type: ArgType::ARG_ANYTHING,
    arg2_type: ArgType::ARG_PTR_TO_MEM | MEM_RDONLY,
    arg3_type: ArgType::ARG_CONST_SIZE,
};