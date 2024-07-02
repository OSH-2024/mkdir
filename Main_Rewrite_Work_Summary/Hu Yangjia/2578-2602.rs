use std::os::raw::c_ulong;
use std::ffi::c_char;

#[cfg(feature = CONFIG_FPROBE)]

struct bpf_kprobe_multi_link
{
    link: bpf_link,
    fp: fprobe,
    addrs: *mut c_ulong,
    cookies: *mut u64,
    cnt: u32,
    mods_cnt: u32,
    mods: *mut *mut module,
    flags: u32
}

struct bpf_kprobe_multi_run_ctx
{
    run_ctx: bpf_run_ctx,
    link: *mut bpf_kprobe_multi_link,
    entry_ip: c_ulong
}

struct user_syms
{
    syms: *mut *mut c_char,
    buf: *mut c_char
}