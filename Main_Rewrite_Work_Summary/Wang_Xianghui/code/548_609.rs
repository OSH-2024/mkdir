// // 假设的外部内容，用于提供必要的上下文
// const BPF_F_INDEX_MASK: u64 = 0x...; // 假设的掩码值
// const BPF_F_CURRENT_CPU: u64 = 0x...; // 表示当前CPU的特殊值
// const EINVAL: i32 = -22; // 无效参数错误码
// const E2BIG: i32 = -7; // 参数太大错误码
// const ENOENT: i32 = -2; // 没有该文件或目录的错误码

// // 假设的结构体和函数
// struct BpfMap {
//     // ...
// }

// struct BpfArray {
//     map: BpfMap,
//     ptrs: Vec<*mut BpfEventEntry>, // 使用裸指针，因为Rust不允许直接对应C的指针操作
//     // ...
// }

// struct BpfEventEntry {
//     event: *mut PerfEvent, // 假设的性能事件结构体指针
//     // ...
// }

struct BpfPerfEventValue {
    counter: u64,
    enabled: u64,
    running: u64,
}

// 假设的外部函数
// fn smp_processor_id() -> u32 { ... }
// fn perf_event_read_local(event: *mut PerfEvent, value: &mut u64, enabled: &mut u64, running: &mut u64) -> i32 { ... }
// fn memset(buf: &mut [u8], value: u8, size: usize) { ... }

// Rust中的内联总是使用`#[inline(always)]`属性
#[inline(always)]
fn get_map_perf_counter(map: &BpfMap, flags: u64, value: &mut u64, enabled: Option<&mut u64>, running: Option<&mut u64>) -> Result<(), i32> {
    // 使用`unsafe`块来调用不安全的操作，如裸指针解引用
    unsafe {
        let array = &*(map as *const _ as *const BpfArray); // 类型转换
        let cpu = smp_processor_id();
        let mut index = flags & BPF_F_INDEX_MASK;
        if flags & !BPF_F_INDEX_MASK != 0 {
            return Err(EINVAL);
        }
        if index == BPF_F_CURRENT_CPU {
            index = cpu as u64;
        }
        if index >= array.map.max_entries as u64 {
            return Err(E2BIG);
        }
        let ee = *array.ptrs.get(index as usize).ok_or(ENOENT)?;
        if ee.is_null() {
            return Err(ENOENT);
        }
        // 假设perf_event_read_local是安全的
        perf_event_read_local((*ee).event, value, enabled.unwrap_or(&mut 0), running.unwrap_or(&mut 0))?;
    }
    Ok(())
}

// 使用宏来模拟C中的宏定义函数
macro_rules! bpf_call {
    ($name:ident, $map:expr, $flags:expr, $buf:expr, $size:expr) => {
        match $name($map, $flags, $buf, $size) {
            Ok(_) => 0,
            Err(e) => e,
        }
    };
}

// Rust不支持直接的函数重载，所以使用不同的函数名
fn bpf_perf_event_read(map: &BpfMap, flags: u64) -> Result<u64, i32> {
    let mut value = 0;
    get_map_perf_counter(map, flags, &mut value, None, None)?;
    Ok(value)
}

fn bpf_perf_event_read_value(map: &BpfMap, flags: u64, buf: &mut BpfPerfEventValue, size: u32) -> Result<(), i32> {
    if size as usize != std::mem::size_of::<BpfPerfEventValue>() {
        // 使用Rust的内置函数来清零
        *buf = BpfPerfEventValue { counter: 0, enabled: 0, running: 0 };
        return Err(EINVAL);
    }
    get_map_perf_counter(map, flags, &mut buf.counter, Some(&mut buf.enabled), Some(&mut buf.running))
}