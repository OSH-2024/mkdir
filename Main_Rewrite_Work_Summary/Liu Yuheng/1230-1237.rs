use std::ffi::c_void;
use std::ptr::NonNull;

fn get_func_ret(ctx: NonNull<c_void>, value: NonNull<u64>) -> i32 {
    unsafe {
        // 将 ctx 转换为 *mut u64 指针，以便进行算术操作
        let ctx_ptr = ctx.as_ptr() as *mut u64;

        // 获取 nr_args 的值。由于 ctx 指向的是 u64 数组，我们可以通过偏移 -1 来访问数组前一个元素
        let nr_args = *ctx_ptr.offset(-1);

        // 根据 nr_args 的值，从 ctx 指向的数组中获取相应的值，并将其写入 value 指向的位置
        *value.as_ptr() = *ctx_ptr.offset(nr_args as isize);
    }

    0 // 按照原始宏的定义，这里返回 0
}