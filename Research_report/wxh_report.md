# 相关工作

# RUST for Linux 项目
<https://github.com/Rust-for-Linux>

<https://rust-for-linux.com/>

# 项目背景
2021 年 4 月 14 号，一封主题名为《Rust support》的邮件出现在 LKML 邮件组中。这封邮件主要介绍了向内核引入 Rust 语言支持的一些看法以及所做的工作。邮件的发送者是 Miguel Ojeda，为内核中 Compiler attributes、.clang-format 等多个模块的维护者，也是目前 Rust for Linux 项目的维护者。

Rust for Linux 项目目前得到了 Google 的大力支持，Miguel Ojeda 当前的全职工作就是负责 Rust for Linux 项目。

长期以来，内核使用 C 语言和汇编语言作为主要的开发语言，部分辅助语言包括 Python、Perl、shell 被用来进行代码生成、打补丁、检查等工作。2016 年 Linux 25 岁生日时，在对 Linus Torvalds 的一篇 采访中，他就曾表示过：

这根本不是一个新现象。我们有过使用 Modula-2 或 Ada 的系统人员，我不得不说 Rust 看起来比这两个灾难要好得多。
我对 Rust 用于操作系统内核并不信服（虽然系统编程不仅限于内核），但同时，毫无疑问，C 有很多局限性。
在最新的对 Rust support 的 RFC 邮件的回复中，他更是说：

所以我对几个个别补丁做了回应，但总体上我不讨厌它。
没有用他特有的回复方式来反击，应该就是暗自喜欢了吧。

# 项目方向
1. 使用Rust使内核更稳定
2. 为内核添加功能支持：语言本身、标准库、编译器、rustdoc、Clippy、bindgen 等方面
3. 子项目的开发，如 klint 和 pinned-init。
4.  Coccinelle for Rust 项目。
5.  rustc_codegen_gcc 项目，该项目将被内核用于 GCC 构建。
6. gccrs 项目，该项目最终将为 GCC 构建提供第二个工具链。
7. 改善 Rust 在 pahole 中的支持。

#### klint
klint 是一个工具，允许在 Rust 内核代码中引入额外的静态分析步骤（"lints"），利用 Rust 编译器作为库。其中一项最早提供的 lint 用于验证 Rust 代码是否遵循内核的锁定规则，通过在编译时跟踪抢占计数来实现。

#### pinned-init
pinned-init 是一个工具，用于初始化内核。它的目标是在内核启动时初始化内核，以便在内核启动后不再需要初始化。这样可以减少内核启动时间，提高性能。
pinned-init 是解决“安全固定初始化问题”的解决方案。它通过使用原地构造函数，提供了对固定结构的安全和可失败初始化。这样，内核可以在启动时初始化这些结构，而不需要在运行时进行初始化。

#### Coccinelle for Rust
Coccinelle 是一个用于自动程序匹配和转换的工具，最初是为了对 Linux 内核源代码（即 C 代码）进行大规模更改而开发的。匹配和转换是由用户指定的转换规则驱动的，这些规则采用抽象化的补丁形式，被称为语义补丁（semantic patches）。随着 Linux 内核以及系统软件在更广泛范围内开始采用 Rust，我们正在为 Rust 开发 Coccinelle，以将 Coccinelle 的强大功能应用于 Rust 代码库中。

#### NVMe Driver
Rust NVMe驱动程序是一项旨在在Linux内核中使用安全的Rust语言实现PCI NVMe驱动程序的工作。该驱动程序的目的是为安全的Rust抽象提供开发平台，并证明Rust作为高性能设备驱动程序实现语言的可行性。

Linux Rust NVMe驱动程序位于此处。这个分支经常基于上游Linux发布版本进行变基。请注意，nvme分支会在没有通知的情况下进行强制推送。基于已弃用的rust分支的版本可在此处找到。

#### null block driver
Rust的null块驱动程序rnull是一个旨在使用Rust实现null_blk的替代方案的工作。

null块驱动程序是评估Rust与块层绑定的良好机会。它是一个小巧简单的驱动程序，因此应该很容易理解。而且，null块驱动程序通常不会部署在生产环境中。因此，它应该相当容易进行审查，任何潜在问题也不会影响到生产负载。

由于其规模小、简单，null块驱动程序是向Linux内核存储社区介绍Rust的好机会。这将有助于为未来的Rust项目做好准备，并促进这些项目更好的维护流程。

从C null_blk驱动程序的提交日志统计（移动之前）显示，C null块驱动程序过去存在大量与内存安全相关的问题。41%的合并修复都是针对内存安全问题的修复。这使得null块驱动程序成为了用Rust重写的一个很好的候选项。

该驱动程序完全采用安全的Rust语言实现，所有不安全的代码都完全包含在封装C API的抽象中。


#### 


# 项目进展

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

在menuconfig 中，可以看到 Rust 的选项，如下所示：



```shell

 //Rust支持（CONFIG_RUST）需要在 General setup 菜单中启用。在其他要求得到满足的情 况下，该选项只有在找到合适的Rust工具链时才会显示（见上文）。相应的，这将使依赖Rust的其 他选项可见。

Kernel hacking
    -> Sample kernel code
        -> Rust samples

```


除此之外，Rust for Linux 项目还有一些子项目，如 klint 和 pinned-init。klint 是一个用于检查内核代码的工具，pinned-init 是一个用于初始化内核的工具。此外，还有 Coccinelle for Rust 项目，该项目用于将 Coccinelle 脚本转换为 Rust 代码。



# 官方开发指导
<https://www.kernel.org/doc/html/latest/translations/zh_CN/rust/coding-guidelines.html>


## 风格和格式化

代码应该使用 `rustfmt` 进行格式化。这样一来，一个不时为内核做贡献的人就不需要再去学习和记忆一个样式指南了。更重要的是，审阅者和维护者不需要再花时间指出风格问题，这样就可以减少补丁落地所需的邮件往返。

**Note**: `rustfmt` 不检查注释和文档的约定。因此，这些仍然需要照顾到。

使用 `rustfmt` 的默认设置。这意味着遵循Rust的习惯性风格。例如，缩进时使用4个空格而不是制表符。

在输入、保存或提交时告知编辑器/IDE进行格式化是很方便的。然而，如果因为某些原因需要在某个时候重新格式化整个内核Rust的源代码，可以运行以下程序:

```bash
make LLVM=1 rustfmt
```

也可以检查所有的东西是否都是格式化的（否则就打印一个差异），例如对于一个CI，用:

```bash
make LLVM=1 rustfmtcheck
```

像内核其他部分的 `clang-format` 一样， `rustfmt` 在单个文件上工作，并且不需要内核配置。有时，它甚至可以与破碎的代码一起工作。

## 注释

“普通”注释（即以 `//` 开头，而不是 `///` 或 `//!` 开头的代码文档）的写法与文档注释相同，使用Markdown语法，尽管它们不会被渲染。这提高了一致性，简化了规则，并允许在这两种注释之间更容易地移动内容。

比如说:

```rust
// `object` is ready to be handled now.
f(object);
```

此外，就像文档一样，注释在句子的开头要大写，并以句号结束（即使是单句）。这包括 `// SAFETY:`, `// TODO:` 和其他“标记”的注释，例如:

```rust
// FIXME: The error should be handled properly.
```

注释不应该被用于文档的目的：注释是为了实现细节，而不是为了用户。即使源文件的读者既是API的实现者又是用户，这种区分也是有用的。事实上，有时同时使用注释和文档是很有用的。例如，用于 `TODO` 列表或对文档本身的注释。

对于后一种情况，注释可以插在中间；也就是说，离要注释的文档行更近。对于其他情况，注释会写在文档之后，例如:

```rust
/// Returns a new [`Foo`].
///
/// # Examples
///
// TODO: Find a better example.
/// ```
/// let foo = f(42);
/// ```
// FIXME: Use fallible approach.
pub fn f(x: i32) -> Foo {
    // ...
}
```

一种特殊的注释是 `// SAFETY:` 注释。这些注释必须出现在每个 `unsafe` 块之前，它们解释了为什么该块内的代码是正确/健全的，即为什么它在任何情况下都不会触发未定义行为，例如:

```rust
// SAFETY: `p` is valid by the safety requirements.
unsafe { *p = 0; }
```

`// SAFETY:` 注释不能与代码文档中的 `# Safety` 部分相混淆。 `# Safety` 部分指定了（函数）调用者或（特性）实现者需要遵守的契约。 `// SAFETY:` 注释显示了为什么一个（函数）调用者或（特性）实现者实际上尊重了 `# Safety` 部分或语言参考中的前提条件。

## 代码文档

Rust内核代码不像C内核代码那样被记录下来（即通过kernel-doc）。取而代之的是用于记录Rust代码的常用系统：rustdoc工具，它使用Markdown（一种轻量级的标记语言）。

要学习Markdown，外面有很多指南。例如:

[Markdown Guide](https://commonmark.org/help/)

一个记录良好的Rust函数可能是这样的:

```rust
/// Returns the contained [`Some`] value, consuming the `self` value,
/// without checking that the value is not [`None`].
///
/// # Safety
///
/// Calling this method on [`None`] is *[undefined behavior]*.
///
/// [undefined behavior]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html
///
/// # Examples
///
/// ```
/// let x = Some("air");
/// assert_eq!(unsafe { x.unwrap_unchecked() }, "air");
/// ```
pub unsafe fn unwrap_unchecked(self) -> T {
    match self {
        Some(val) => val,

        // SAFETY: The safety contract must be upheld by the caller.
        None => unsafe { hint::unreachable_unchecked() },
    }
}
```

这个例子展示了一些 `rustdoc` 的特性和内核中遵循的一些惯例:

- 第一段必须是一个简单的句子，简要地描述被记录的项目的作用。进一步的解释必须放在额外的段落中。
- 不安全的函数必须在 `# Safety` 部分记录其安全前提条件。
- 虽然这里没有显示，但如果一个函数可能会恐慌，那么必须在 `# Panics` 部分描述发生这种情况的条件。
- 请注意，恐慌应该是非常少见的，只有在有充分理由的情况下才会使用。几乎在所有的情况下，都应该使用一个可失败的方法，通常是返回一个 `Result`。
- 如果提供使用实例对读者有帮助的话，必须写在一个叫做`# Examples`的部分。

Rust项目（函数、类型、常量……）必须有适当的链接(`rustdoc` 会自动创建一个链接)。

任何 `unsafe` 的代码块都必须在前面加上一个 `// SAFETY:` 的注释，描述里面的代码为什么是正确的。

虽然有时原因可能看起来微不足道，但写这些注释不仅是记录已经考虑到的问题的好方法，最重要的是，它提供了一种知道没有额外隐含约束的方法。

要了解更多关于如何编写Rust和拓展功能的文档，请看看 `rustdoc` 这本书，网址是:

[Rustdoc Documentation Guide](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)

## 命名

Rust内核代码遵循通常的Rust命名空间:

[Rust API Naming Guidelines](https://rust-lang.github.io/api-guidelines/naming.html)

当现有的C语言概念（如宏、函数、对象......）被包装成Rust抽象时，应该使用尽可能接近C语言的名称，以避免混淆，并在C语言和Rust语言之间来回切换时提高可读性。例如，C语言中的 `pr_info` 这样的宏在Rust中的命名是一样的。

说到这里，应该调整大小写以遵循Rust的命名惯例，模块和类型引入的命名间隔不应该在项目名称中重复。例如，在包装常量时，如:

```rust
#define GPIO_LINE_DIRECTION_IN  0
#define GPIO_LINE_DIRECTION_OUT 1
```

在Rust中的等价物可能是这样的（忽略文档）.:

```rust
pub mod gpio {
    pub enum LineDirection {
        In = bindings::GPIO_LINE_DIRECTION_IN as _,
        Out = bindings::GPIO_LINE_DIRECTION_OUT as _,
    }
}
```

也就是说， `GPIO_LINE_DIRECTION_IN` 的等价物将被称为 `gpio::LineDirection::In`。特别是，它不应该被命名为 `gpio::gpio_line_direction::GPIO_LINE_DIRECTION_IN`。






# 官方背书
Rust 成为 Linux 内核第二官方语言

<https://docs.kernel.org/rust/index.html>


要想深入了解，可以看Linux源码树 samples/rust/ 下的样例源代码、 rust/ 下的Rust支持代码和 Kernel hacking 下的 Rust hacking 菜单。





#### 参考文献
1.  如何用 Rust 编写一个 Linux 内核模块 | Linux 中国 
    <https://zhuanlan.zhihu.com/p/387076919>

2. 官方文档 
    <https://rust-for-linux.com/>


