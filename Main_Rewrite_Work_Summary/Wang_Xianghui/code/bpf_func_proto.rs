pub struct BpfFuncProto {
    func: fn() -> (), // 这是一个函数指针，将来需要根据实际的函数签名进行修改
    gpl_only: bool,
    ret_type: RetType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
    arg1_type: ArgType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
    arg2_type: ArgType, // 这是一个枚举或者其他类型，将来需要根据实际情况进行定义
}

// 将来需要根据实际情况定义这些类型
pub enum RetType {
    RetInteger,
    // 其他返回类型
}

pub enum ArgType {
    ArgPtrToMem,
    ArgConstSize,
    // 其他参数类型
}