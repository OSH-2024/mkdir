// 文档注释：调用BPF程序的`trace_call_bpf`函数
// @call: tracepoint事件
// @ctx: 不透明的上下文指针
//
// kprobe处理程序通过此助手执行BPF程序。
// 将来可以从静态tracepoints中使用。
//
// 返回：BPF程序总是返回一个整数，kprobe处理程序将其解释为：
// 0 - 从kprobe返回（事件被过滤掉）
// 1 - 将kprobe事件存储到环形缓冲区中
// 其他值保留，当前与1相同