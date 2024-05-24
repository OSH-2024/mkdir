macro_rules! BPF_CALL_2 {
    ($func:ident, $arg1:ty, $arg2:ty) => {
        pub fn $func(ctx: *mut c_void, value: *mut u64) -> i32 {
            unsafe {
                let nr_args = *((ctx as *mut u64).offset(-1));
                *value = *((ctx as *mut u64).offset(nr_args as isize));
            }
            0
        }
    };
}