# Linux内核测试指南

有许多不同的工具可以用于测试Linux内核，因此了解什么时候使用它们可能 很困难。本文档粗略概述了它们之间的区别，并阐释了它们是怎样糅合在一起 的。

## 编写和运行测试

大多数内核测试都是用kselftest或KUnit框架之一编写的。它们都让运行测试 更加简化，并为编写新测试提供帮助。

如果你想验证内核的行为——尤其是内核的特定部分——那你就要使用kUnit或 kselftest。

### KUnit和kselftest的区别

**KUnit**（KUnit - Linux Kernel Unit Testing）是用于“白箱”测试的一个完整的内核内部系统：因为测试代码是内核的一部分，所以它能够访问用户空间不能访问到的内部结构和功能。

```c
// 示例KUnit测试
static void example_test(struct kunit *test)
{
    int result = some_kernel_function();
    KUNIT_EXPECT_EQ(test, result, expected_value);
}

// 在测试模块中注册测试
static struct kunit_case example_test_cases[] = {
    KUNIT_CASE(example_test),
    {}
};

static struct kunit_suite example_test_suite = {
    .name = "example_test_suite",
    .test_cases = example_test_cases,
};
kunit_test_suites(&example_test_suite);
```
**kselftest**（Linux Kernel Selftests），相对来说，大量用于用户空间，并且通常测试用户空间的脚本或程序。

## 示例kselftest脚本
#!/bin/bash
```C
echo "Running self-test..."
result=$(your_test_command)
if [ "$result" -ne "expected_value" ]; then
    echo "Test failed!"
    exit 1
fi
echo "Test passed!"
```
### 选择测试框架
- KUnit：测试单个内核功能或代码路径，构建和运行速度快，适合开发流程中的频繁运行。
- kselftest：适合测试通过某种方式导出到用户空间的内核功能，适合功能完整的测试。
## 代码覆盖率工具
### gcov
在Linux内核里使用gcov做代码覆盖率检查。它能用于获取内核的全局或每个模块的覆盖率。

```c
// 启用gcov支持的Makefile片段
CONFIG_DEBUG_FS=y
CONFIG_GCOV_KERNEL=y
```
### KCOV
用于模糊测试和捕捉每个任务的覆盖率，适合在单一系统调用里使用。

```c
// 启用KCOV支持的Makefile片段
CONFIG_KCOV=y
```
## 动态分析工具
### kmemleak
检测可能的内存泄漏。
```c
// 启用kmemleak支持的Makefile片段
CONFIG_DEBUG_KMEMLEAK=y
```
### KASAN
检测非法内存访问，如数组越界和释放后重用（UAF）。

```c
// 启用KASAN支持的Makefile片段
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
```
### UBSAN
检测C标准中未定义的行为，如整型溢出。

```c
// 启用UBSAN支持的Makefile片段
CONFIG_UBSAN=y
CONFIG_UBSAN_SANITIZE_ALL=y
```
### KCSAN
检测数据竞争。

```c
// 启用KCSAN支持的Makefile片段
CONFIG_KCSAN=y
CONFIG_KCSAN_REPORT_ONCE_IN_MS=1000
```
### KFENCE
低开销的内存问题检测器，比KASAN更快。

```c
// 启用KFENCE支持的Makefile片段
CONFIG_KFENCE=y
```
### lockdep
锁定正确性检测器。

```c
// 启用lockdep支持的Makefile片段
CONFIG_LOCKDEP=y
```
## 静态分析工具
除了测试运行中的内核，我们还可以使用静态分析工具直接分析内核的源代码（在编译时）。内核中常用的工具允许人们检查整个源代码树或其中的特定文件。

### Sparse
通过执行类型检查、锁检查、值范围检查来帮助测试内核。

```bash
# 使用Sparse进行类型检查
make C=1 CHECK="sparse" <your-target>
```
### Smatch
扩展了Sparse，并提供编程逻辑错误的检查。

```bash
# 使用Smatch进行逻辑错误检查
make C=2 CHECK="smatch" <your-target>
```
### Coccinelle
帮助源代码的重构和并行演化。

```bash
# 使用Coccinelle进行代码重构
coccicheck
```
## 何时使用Sparse和Smatch
- Sparse：验证注释变量、检测指针使用不当、分析符号初始化器的兼容性。
- Smatch：进行流程分析，检测缓冲区分配、索引控制等问题。
## Smatch和Coccinelle的强项
- Coccinelle：适合宏中的错误检查，可以创建补丁进行大规模代码转换。
- Smatch：分析变量值，适合检测缓冲区分配、索引控制等问题。