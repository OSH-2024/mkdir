extern "C"
{
    fn get_kernel_nofault(instr: u32, fentry_ip: *mut u32) -> u32;
    fn is_endbr(instr: u32) -> u32;
    const ENDBR_INSN_SIZE: u32;
}

pub fn get_entry_ip(fentry_ip: u64) -> u64 {
    let instr: u32;
    if unsafe { get_kernel_nofault(instr, fentry_ip as *mut u32) } != 0 {
        return fentry_ip;
    }
    if unsafe { is_endbr(instr) } != 0 {
        return fentry_ip - unsafe { ENDBR_INSN_SIZE } as u64;
    }
    return fentry_ip;
}