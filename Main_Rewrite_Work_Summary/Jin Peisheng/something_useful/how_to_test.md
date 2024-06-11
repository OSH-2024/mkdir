# 测试单元编写思路
## 设置测试环境：

创建一个包含测试脚本和预期输出的测试目录。
编写用于执行bpftrace命令的Python函数。
## 编写测试用例：

编写每个bpftrace命令的测试用例。
捕获bpftrace命令的输出并与预期输出进行比较。
## 运行测试：

使用unittest库运行所有测试用例。
下面是一个示例代码，展示了如何实现上述步骤：

```python
import subprocess
import unittest
import os

class BpftraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 设置测试环境，比如创建必要的测试目录
        cls.test_dir = "bpftrace_tests"
        os.makedirs(cls.test_dir, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        # 清理测试环境
        os.rmdir(cls.test_dir)

    def run_bpftrace(self, script):
        # 执行bpftrace脚本并返回输出
        result = subprocess.run(['bpftrace', '-e', script], capture_output=True, text=True)
        return result.stdout

    def test_list_probes(self):
        script = 'tracepoint:syscalls:sys_enter_*'
        expected_output = "..."
        output = self.run_bpftrace(script)
        self.assertIn(expected_output, output)

    def test_hello_world(self):
        script = 'BEGIN { printf("hello world\n"); }'
        expected_output = "hello world\n"
        output = self.run_bpftrace(script)
        self.assertIn(expected_output, output)

    def test_file_open(self):
        script = 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
        # 假设我们知道某个文件会在测试期间被打开
        expected_output = "some_process /some/file\n"
        output = self.run_bpftrace(script)
        self.assertIn(expected_output, output)

    def test_syscall_count(self):
        script = 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
        # 在测试期间我们可以触发一些系统调用
        expected_output = "@[some_process]:"
        output = self.run_bpftrace(script)
        self.assertIn(expected_output, output)

    def test_read_distribution(self):
        pid = 12345  # 用实际的pid替换
        script = f'tracepoint:syscalls:sys_exit_read /pid == {pid}/ {{ @bytes = hist(args->ret); }}'
        # 触发read系统调用
        expected_output = "@bytes:\n[0, 1]"
        output = self.run_bpftrace(script)
        self.assertIn(expected_output, output)

if __name__ == '__main__':
    unittest.main()
```
## 说明

1. setUpClass和tearDownClass:

    setUpClass方法用于在所有测试开始之前设置测试环境。
    tearDownClass方法用于在所有测试完成之后清理测试环境。
2. run_bpftrace方法:

    该方法使用subprocess.run执行bpftrace命令，并捕获其输出。
3. 各个测试用例:

    每个测试用例定义一个bpftrace脚本并比较其输出与预期输出。

# bpftrace测试
1. 列出所有探针
```sh
bpftrace -l 'tracepoint:syscalls:sys_enter_*'
```
使用 bpftrace -l 列出所有探测点，并可以添加搜索项。
探针用于捕获事件数据，支持通配符如 * 和 ?。

2. Hello World
```sh
bpftrace -e 'BEGIN { printf("hello world\n"); }'
```
打印欢迎消息，BEGIN 探针在程序开始时触发，用于设置变量和打印消息头。
3. 文件打开
```sh
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
```
跟踪文件打开时打印进程名和文件名。
使用 tracepoint 探针类型，捕获 openat 系统调用的事件。
4. 进程的系统调用记数统计
```sh
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```
统计进程的系统调用计数，并在按 Ctrl-C 后打印结果。
5. read() 分布统计
```sh
bpftrace -e 'tracepoint:syscalls:sys_exit_read /pid == 18644/ { @bytes = hist(args->ret); }'
```
跟踪指定进程号的 read() 系统调用并打印直方图。
6. 内核动态跟踪 read() 的字节数
```sh
bpftrace -e 'kretprobe:vfs_read { @bytes = lhist(retval, 0, 2000, 200); }'
```
使用内核动态跟踪技术显示 read() 返回字节数的直方图。
7. read() 调用的时间
```sh
bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns[comm] = hist(nsecs - @start[tid]); delete(@start[tid]); }'
```
以纳秒为单位显示 read() 调用花费的时间，使用内核探针 kprobe 和 kretprobe。
8. 统计进程级别的事件
```sh
bpftrace -e 'tracepoint:sched:sched* { @[probe] = count(); } interval:s:5 { exit(); }'
```
统计 5 秒内进程级的事件并打印。
9. 分析内核实时函数栈
```sh
bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'
```
以 99 赫兹的频率分析内核调用栈并打印次数统计。
10.  调度器跟踪
```sh
bpftrace -e 'tracepoint:sched:sched_switch { @[kstack] = count(); }'
```
统计进程上下文切换次数并打印调用栈。
11.  块级 I/O 跟踪
```sh
bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args->bytes); }'
```
打印块 I/O 请求字节数的直方图。
12.  内核结构跟踪
```sh
# cat path.bt
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
    printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name));
}

# bpftrace path.bt
```
使用内核动态跟踪技术跟踪 vfs_open 函数，打印打开的路径名。
