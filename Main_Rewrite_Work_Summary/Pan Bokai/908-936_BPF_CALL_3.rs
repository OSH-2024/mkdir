//908-936
// BPF_CALL_3 宏的 Rust 实现
macro_rules! BPF_CALL_3 {
    ($func:ident, $($arg:ty),+) => {
        pub fn $func(path: *mut Path, buf: *mut c_char, sz: u32) -> i64 {
            let mut copy = Path::default();
            let mut len: i64;
            let mut p: *mut c_char;

            if sz == 0 {
                return 0;
            }

            /*翻译：
             * path 指针已经被验证为可信和安全的,
             * 但是让我们再次检查它的有效性,以解决
             * 可能存在的验证器错误。
             */
            len = copy_from_kernel_nofault(&mut copy, path, std::mem::size_of::<Path>());
            if len < 0 {
                return len;
            }

            p = d_path(&copy, buf, sz);
            if p.is_null() {
                len = p as i64;
            } else {
                len = (buf as usize + sz as usize - p as usize) as i64;
                unsafe {
                    std::ptr::copy(p, buf, len as usize);
                }
            }

            len
        }
    };
}