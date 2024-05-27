// src/lib.rs

use std::ptr;

#[derive(Clone, Copy)]
enum PidType {
    PidTypeTgid,
}

#[derive(Clone, Copy)]
struct TaskStruct {
    flags: u32,
}

static PF_KTHREAD: u32 = 0x00200000;
static PF_EXITING: u32 = 0x00000004;
static SEND_SIG_PRIV: u32 = 0;

static mut CURRENT: TaskStruct = TaskStruct { flags: 0 };
static mut IRQ_DISABLED: bool = false;
static mut VALID_SIGNAL: bool = true;
static mut IRQ_WORK_BUSY: bool = false;
static mut IS_GLOBAL_INIT: bool = false;
static mut NMI_UACCESS_OKAY: bool = true;

impl TaskStruct {
    fn new(flags: u32) -> Self {
        TaskStruct { flags }
    }
}

struct IrqWork;

impl IrqWork {
    fn is_busy(&self) -> bool {
        unsafe { IRQ_WORK_BUSY }
    }

    fn queue(&self) {}
}

struct SendSignalIrqWork {
    irq_work: IrqWork,
    task: TaskStruct,
    sig: u32,
    type_: PidType,
}

fn get_task_struct(task: &TaskStruct) -> TaskStruct {
    TaskStruct::new(task.flags)
}

fn valid_signal(_sig: u32) -> bool {
    unsafe { VALID_SIGNAL }
}

fn is_global_init(_task: &TaskStruct) -> bool {
    unsafe { IS_GLOBAL_INIT }
}

fn nmi_uaccess_okay() -> bool {
    unsafe { NMI_UACCESS_OKAY }
}

fn group_send_sig_info(_sig: u32, _priv: u32, _task: &TaskStruct, _type_: PidType) -> i32 {
    0
}

fn irqs_disabled() -> bool {
    unsafe { IRQ_DISABLED }
}

fn this_cpu_ptr<T>(_: &T) -> &'static mut T {
    unsafe { &mut *(ptr::null_mut() as *mut T) }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_task(flags: u32) -> TaskStruct {
        TaskStruct { flags }
    }

    fn mock_current_task(flags: u32) {
        unsafe {
            CURRENT = setup_task(flags);
        }
    }

    fn mock_irqs_disabled(disabled: bool) {
        unsafe {
            IRQ_DISABLED = disabled;
        }
    }

    fn mock_valid_signal(valid: bool) {
        unsafe {
            VALID_SIGNAL = valid;
        }
    }

    fn mock_irq_work_busy(busy: bool) {
        unsafe {
            IRQ_WORK_BUSY = busy;
        }
    }

    fn mock_is_global_init(global_init: bool) {
        unsafe {
            IS_GLOBAL_INIT = global_init;
        }
    }

    fn mock_nmi_uaccess_okay(okay: bool) {
        unsafe {
            NMI_UACCESS_OKAY = okay;
        }
    }

    #[test]
    fn test_task_flags_kthread_or_exiting() {
        mock_current_task(PF_KTHREAD);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -1);

        mock_current_task(PF_EXITING);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -1);
    }

    #[test]
    fn test_nmi_uaccess_not_okay() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(false);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -1);
    }

    #[test]
    fn test_global_init_task() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(true);
        mock_is_global_init(true);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -1);
    }

    #[test]
    fn test_irqs_disabled_invalid_signal() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(true);
        mock_is_global_init(false);
        mock_irqs_disabled(true);
        mock_valid_signal(false);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -22);
    }

    #[test]
    fn test_irqs_disabled_irq_work_busy() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(true);
        mock_is_global_init(false);
        mock_irqs_disabled(true);
        mock_valid_signal(true);
        mock_irq_work_busy(true);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), -16);
    }

    #[test]
    fn test_irqs_disabled_success() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(true);
        mock_is_global_init(false);
        mock_irqs_disabled(true);
        mock_valid_signal(true);
        mock_irq_work_busy(false);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), 0);
    }

    #[test]
    fn test_group_send_sig_info_success() {
        mock_current_task(0);
        mock_nmi_uaccess_okay(true);
        mock_is_global_init(false);
        mock_irqs_disabled(false);
        assert_eq!(bpf_send_signal_common(9, PidType::PidTypeTgid), 0);
    }
}
