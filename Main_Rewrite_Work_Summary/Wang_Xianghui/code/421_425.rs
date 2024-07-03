struct BpfFuncProto;

static mut BPF_TRACE_PRINTK_PROTO: BpfFuncProto = BpfFuncProto;

// fn set_printk_clr_event() {
//     // 这里是实现,在别的部分
// }

fn bpf_get_trace_printk_proto() -> &'static BpfFuncProto {
    set_printk_clr_event();
    unsafe { &BPF_TRACE_PRINTK_PROTO }
}