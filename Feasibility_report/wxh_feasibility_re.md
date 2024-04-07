# 从源码视角分析可行性
分析以下部分：
1. samples/rust/ 下的样例源代码
2. Kernel hacking 下的 Rust hacking 菜单

## samples/rust/ 下的样例源代码 
```shell
$ tree samples/rust/
.
├── hostprogs
│   ├── a.rs
│   ├── b.rs
│   ├── Makefile
│   └── single.rs
├── Kconfig
├── Makefile
├── rust_minimal.rs
└── rust_print.rs
```

**rust_minimal.rs是一个使用 Rust 编写的 Linux 内核模块的最小示例**


```rust
use kernel::prelude::*; //导入了 kernel::prelude 模块中的所有公共项。这是 Rust 中常见的模式，用于简化对常用项的引用


/*这是一个宏调用，用于定义一个内核模块。它设置了模块的类型、名称、作者、描述和许可证。*/
module! {
    type: RustMinimal,
    name: "rust_minimal",
    author: "Rust for Linux Contributors",
    description: "Rust minimal sample",
    license: "GPL",
}

/*这定义了一个名为 RustMinimal 的结构体，它有一个名为 numbers 的字段，类型为 Vec<i32>。*/
struct RustMinimal {
    numbers: Vec<i32>,
}


/*这是 RustMinimal 的实现。它实现了 kernel::Module trait，这是一个由 Rust for Linux 提供的 trait，用于定义内核模块。
它是为 RustMinimal 结构体实现 kernel::Module trait 的代码。它定义了 init 方法，该方法在模块初始化时被调用。这个方法创建了一个新的 Vec<i32>，向其中添加了一些数字，然后返回一个新的 RustMinimal 实例
*/
impl kernel::Module for RustMinimal {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rust minimal sample (init)\n");
        pr_info!("Am I built-in? {}\n", !cfg!(MODULE));

        let mut numbers = Vec::new();
        numbers.try_push(72)?;
        numbers.try_push(108)?;
        numbers.try_push(200)?;

        Ok(RustMinimal { numbers })
    }
}

/*这是为 RustMinimal 结构体实现 Drop trait 的代码。Drop trait 的 drop 方法在对象被销毁时被调用。在这个方法中，它打印出存储在 numbers 字段中的数字，然后打印出一个消息，表示模块已经退出*/
impl Drop for RustMinimal {
    fn drop(&mut self) {
        pr_info!("My numbers are {:?}\n", self.numbers);
        pr_info!("Rust minimal sample (exit)\n");
    }
}
```



# Kernel hacking 下的 Rust hacking 菜单
```shell
make menuconfig 
```

![alt text](image.png)

分析如下：
1. `Debug assertions`：这个选项可能会启用 Rust 的 debug 断言，这是一种在 debug 构建中检查代码的方式。如果一个断言失败了，程序会立即终止。这可以帮助开发者找到和修复 bugs。

2. `Overflow checks`：这个选项可能会启用 Rust 的溢出检查。当数值运算结果超出类型能表示的范围时，Rust 会抛出一个溢出错误。这可以防止一些潜在的错误和安全问题。

3. `Allow unoptimized build-time assertions`:这个选项可能会允许在未优化的构建中使用断言。这可能会使得 debug 构建更慢，但是可以提供更多的错误检查。







