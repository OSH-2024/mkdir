DEFINE_PER_CPU(send_signal_irq_work, send_signal_work);
fn do_bpf_send_signal(entry: *mut irq_work) 
{
    let work = container_of(entry, send_signal_work, irq_work);
    group_send_sig_info(work.sig, SEND_SIG_PRIV, work.task, work.type);
    put_task_struct(work.task);
}
