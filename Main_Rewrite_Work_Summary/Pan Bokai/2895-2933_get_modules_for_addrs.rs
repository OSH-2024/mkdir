//2895-2933
// get_modules_for_addrs 函数的 Rust 实现
fn get_modules_for_addrs(addrs: &[u64]) -> Result<Vec<&module>, i32> {
    let mut arr = modules_array::default();
    let mut err = 0;

    // 遍历给定的地址数组
    for addr in addrs {
        // 禁用抢占
        preempt_disable();
        // 根据地址获取对应的模块
        let module = unsafe { __module_address(*addr) };
        // 如果模块不存在或已经存储,启用抢占并继续下一个地址
        if module.is_null() || has_module(&arr, module) {
            preempt_enable();
            continue;
        }
        // 尝试获取模块引用计数
        if !try_module_get(module) {
            err = -EINVAL;
        }
        // 启用抢占
        preempt_enable();
        // 如果出错,跳出循环
        if err != 0 {
            break;
        }
        // 将模块添加到数组中
        err = add_module(&mut arr, module);
        if err != 0 {
            // 如果添加失败,释放模块引用计数并跳出循环
            module_put(module);
            break;
        }
    }

    // 如果出错,释放数组中的模块并返回错误码
    if err != 0 {
        kprobe_multi_put_modules(&arr.mods, arr.mods_cnt);
        return Err(err);
    }

    // 如果一切正常,返回找到的模块数组
    Ok(arr.mods)
}