//2934-2944
// addrs_check_error_injection_list 函数的 Rust 实现
fn addrs_check_error_injection_list(addrs: &[u64]) -> Result<(), i32> {
    // 遍历给定的地址数组
    for addr in addrs {
        // 检查地址是否在错误注入列表中
        if !within_error_injection_list(*addr) {
            // 如果有任何地址不在错误注入列表中,返回错误码 -EINVAL
            return Err(-EINVAL);
        }
    }
    // 如果所有地址都在错误注入列表中,返回 Ok(())
    Ok(())
}