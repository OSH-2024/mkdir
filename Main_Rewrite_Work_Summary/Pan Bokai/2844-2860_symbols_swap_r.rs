//2844-2860
// symbols_swap_r 函数的 Rust 实现
fn symbols_swap_r(a: *mut c_void, b: *mut c_void, size: i32, priv_data: *const c_void) {
    // 将 priv_data 转换为 multi_symbols_sort 结构体的不可变引用
    let data = unsafe { &*(priv_data as *const multi_symbols_sort) };

    // 将 a 和 b 转换为可变的字符串切片引用
    let name_a = unsafe { &mut *(a as *mut &str) };
    let name_b = unsafe { &mut *(b as *mut &str) };

    // 交换 name_a 和 name_b 的值
    std::mem::swap(name_a, name_b);

    // 如果定义了 cookies,则同时交换相关的 cookies
    if let Some(cookies) = data.cookies {
        // 计算 cookie_a 和 cookie_b 的位置
        let cookie_a = unsafe { cookies.offset((name_a as *const _ as usize - data.funcs as usize) as isize) };
        let cookie_b = unsafe { cookies.offset((name_b as *const _ as usize - data.funcs as usize) as isize) };

        // 交换 cookie_a 和 cookie_b 的值
        let cookie_a = unsafe { &mut *cookie_a };
        let cookie_b = unsafe { &mut *cookie_b };
        std::mem::swap(cookie_a, cookie_b);
    }
}