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



### 官方背书
Rust 成为 Linux 内核第二官方语言

<https://docs.kernel.org/rust/index.html>







#### 参考文献
1.  如何用 Rust 编写一个 Linux 内核模块 | Linux 中国 
    
    <https://zhuanlan.zhihu.com/p/387076919>


