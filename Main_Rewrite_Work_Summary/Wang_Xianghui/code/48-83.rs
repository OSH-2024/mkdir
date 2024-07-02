// 引入Rust的标准库中的互斥锁和链表支持
use std::collections::LinkedList;
use std::sync::Mutex;

// 假设的外部Rust结构体和函数
// #[repr(C)]
// struct Module {
//     num_bpf_raw_events: u32,
//     bpf_raw_events: *mut BpfRawEventMap,
// }
// 
// #[repr(C)]
// struct BpfRawEventMap {
//     tp: *const Tracepoint,
// }
// 
// #[repr(C)]
// struct Tracepoint {
//     name: *const c_char,
// }
// 
// extern "C" {
//     fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
//     fn try_module_get(module: *mut Module) -> bool;
// }

// Rust版本的`BpfTraceModule`结构体
struct BpfTraceModule {
    module: *mut Module,
    // Rust中不需要显式地声明链表节点，因为`LinkedList`已经处理了
}

// Rust版本的全局变量和互斥锁
lazy_static! {
    static ref BPF_TRACE_MODULES: Mutex<LinkedList<BpfTraceModule>> = Mutex::new(LinkedList::new());
}

// Rust版本的`bpf_get_raw_tracepoint_module`函数
fn bpf_get_raw_tracepoint_module(name: &str) -> Option<*mut BpfRawEventMap> {
    let bpf_module_mutex = BPF_TRACE_MODULES.lock().unwrap();
    for btm in bpf_module_mutex.iter() {
        let module = unsafe { &*btm.module }; // 不安全地解引用，因为我们正在处理裸指针
        for i in 0..module.num_bpf_raw_events {
            let btp = unsafe { &*module.bpf_raw_events.offset(i as isize) }; // 不安全地访问数组
            let tp_name = unsafe { CStr::from_ptr((*btp.tp).name) }; // 将C字符串转换为Rust字符串
            if tp_name.to_str().unwrap() == name {
                if unsafe { try_module_get(btm.module) } {
                    return Some(btp);
                } else {
                    break;
                }
            }
        }
    }
    None
}