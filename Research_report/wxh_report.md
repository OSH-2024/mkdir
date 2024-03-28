## 相关工作

### RUST for Linux 项目
<https://github.com/Rust-for-Linux>

<https://rust-for-linux.com/>

### 项目背景
2021 年 4 月 14 号，一封主题名为《Rust support》的邮件出现在 LKML 邮件组中。这封邮件主要介绍了向内核引入 Rust 语言支持的一些看法以及所做的工作。邮件的发送者是 Miguel Ojeda，为内核中 Compiler attributes、.clang-format 等多个模块的维护者，也是目前 Rust for Linux 项目的维护者。

Rust for Linux 项目目前得到了 Google 的大力支持，Miguel Ojeda 当前的全职工作就是负责 Rust for Linux 项目。

长期以来，内核使用 C 语言和汇编语言作为主要的开发语言，部分辅助语言包括 Python、Perl、shell 被用来进行代码生成、打补丁、检查等工作。2016 年 Linux 25 岁生日时，在对 Linus Torvalds 的一篇 采访中，他就曾表示过：

这根本不是一个新现象。我们有过使用 Modula-2 或 Ada 的系统人员，我不得不说 Rust 看起来比这两个灾难要好得多。
我对 Rust 用于操作系统内核并不信服（虽然系统编程不仅限于内核），但同时，毫无疑问，C 有很多局限性。
在最新的对 Rust support 的 RFC 邮件的回复中，他更是说：

所以我对几个个别补丁做了回应，但总体上我不讨厌它。
没有用他特有的回复方式来反击，应该就是暗自喜欢了吧。

### 项目方向
1. 使用Rust使内核更稳定
2. 为内核添加功能支持：语言本身、标准库、编译器、rustdoc、Clippy、bindgen 等方面
3. 子项目的开发，如 klint 和 pinned-init。
4.  Coccinelle for Rust 项目。
5.  rustc_codegen_gcc 项目，该项目将被内核用于 GCC 构建。
6. gccrs 项目，该项目最终将为 GCC 构建提供第二个工具链。
7. 改善 Rust 在 pahole 中的支持。

### 项目进展

 在Linux内核中使用 Rust 的工作已经进行了一段时间，目前已经有了一些成果。目前，Rust for Linux 项目已经完成了以下工作：
 在目录 /Linux-Kernel/linux-6.8.1/rust 中，已经有了一些 Rust 代码，包括：


```shell
.
├── alloc    // 内存分配，来自于 Rust 标准库
│   ├── alloc.rs  // 内存分配的实现
│   ├── boxed.rs   // Box 的实现
│   ├── collections  
│   │   └── mod.rs  
│   ├── lib.rs  // alloc 的入口
│   ├── raw_vec.rs   
│   ├── README.md
│   ├── slice.rs  // Slice 的实现
│   └── vec  
├── bindgen_parameters  // bindgen 参数
├── bindings  // 绑定
│   ├── bindings_helper.h
│   └── lib.rs
├── build_error.rs
├── compiler_builtins.rs  // 编译器内建函数
├── exports.c   // 导出
├── helpers.c   // 辅助函数
├── kernel  // 内核相关
│   ├── allocator.rs  // 分配器
│   ├── build_assert.rs
│   ├── error.rs
│   ├── init
│   │   ├── __internal.rs
│   │   └── macros.rs
│   ├── init.rs
│   ├── ioctl.rs
│   ├── kunit.rs  // KUnit 测试框架
│   ├── lib.rs
│   ├── net   // 网络
│   │   └── phy.rs
│   ├── net.rs
│   ├── prelude.rs  // 内核预定义
│   ├── print.rs   // 打印
│   ├── static_assert.rs   // 静态断言
│   ├── std_vendor.rs   
│   ├── str.rs  // 字符串
│   ├── sync  // 同步机制
│   │   ├── arc
│   │   │   └── std_vendor.rs
│   │   ├── arc.rs
│   │   ├── condvar.rs
│   │   ├── lock
│   │   │   ├── mutex.rs
│   │   │   └── spinlock.rs
│   │   ├── locked_by.rs
│   │   └── lock.rs
│   ├── sync.rs
│   ├── task.rs
│   ├── types.rs
│   └── workqueue.rs
├── macros  // 宏定义
│   ├── concat_idents.rs
│   ├── helpers.rs
│   ├── lib.rs
│   ├── module.rs
│   ├── paste.rs
│   ├── pin_data.rs  
│   ├── pinned_drop.rs
│   ├── quote.rs   // 引用
│   ├── vtable.rs   // 虚函数表
│   └── zeroable.rs   
├── Makefile
└── uapi  // 用户态接口
    ├── lib.rs
    └── uapi_helper.h  // 用户态接口辅助
```

在menuconfig 中，可以看到 Rust 的选项，如下图所示：



```shell

 //Rust支持（CONFIG_RUST）需要在 General setup 菜单中启用。在其他要求得到满足的情 况下，该选项只有在找到合适的Rust工具链时才会显示（见上文）。相应的，这将使依赖Rust的其 他选项可见。

Kernel hacking
    -> Sample kernel code
        -> Rust samples

```


除此之外，Rust for Linux 项目还有一些子项目，如 klint 和 pinned-init。klint 是一个用于检查内核代码的工具，pinned-init 是一个用于初始化内核的工具。此外，还有 Coccinelle for Rust 项目，该项目用于将 Coccinelle 脚本转换为 Rust 代码。



### 项目优势


### 官方背书
Rust 成为 Linux 内核第二官方语言

<https://docs.kernel.org/rust/index.html>


要想深入了解，可以看Linux源码树 samples/rust/ 下的样例源代码、 rust/ 下的Rust支持代码和 Kernel hacking 下的 Rust hacking 菜单。





#### 参考文献
1.  如何用 Rust 编写一个 Linux 内核模块 | Linux 中国 
    
    <https://zhuanlan.zhihu.com/p/387076919>


