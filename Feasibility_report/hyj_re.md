# 可行性尝试
## 前言
1. 这是一个偏向实践的报告，逐步讲解怎么实现用Rust改写C的技术障碍。
2. 面临的问题：
   1. Rust形成的函数怎么被更顶层的C语言调用
   2. Rust如何调用更底层的C语言函数
3. 核心：使用静态链接实现

## Rust调用C语言函数
1. 调用C头文件里面的函数        
    关键：直接在`extern "C"`引入即可    
    ```rust
    use std::os::raw::c_int;//f32
    use std::os::raw::c_double;// f64
    extern "C" {
        fn abs(num:c_int) ->c_int;
        fn sqrt(num:c_double) ->c_double;
    }
    fn main()
    {
        println!("call c->abs :{}",unsafe{abs(-32)});  
        println!("call c -> sqrt:{}",unsafe{sqrt(36.0)});
    }
    ```
    执行后得到结果符合预期：
    > call c -> abs :32     
    > call c -> sqrt:6


2. 调用C语言编译完成的静态链接      
    > 平台：vlab  
    > 版本：Vlab01-ubuntu-desktop-18.04.tar.gz  
    > cargo版本：cargo 1.75.0   
    > gcc版本：gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
    
    1. 代码架构：   
    
        ```
        .   
        ├── build.rs    
        ├── c   
        │   ├── example.c   
        │   ├── example.h   
        │   ├── libexample.a    
        │   ├── libexample.o    
        │   ├── main    
        │   ├── Makefile    
        │   └── test.c  
        ├── Cargo.lock  
        ├── Cargo.toml  
        ├── c_fact  
        │   ├── main    
        │   ├── main.c  
        │   └── Makefile    
        ├── src 
        │   └── main.rs  
        └── target  
            ├── CACHEDIR.TAG    
            ├── debug   
            └── release 
                ├── examples    
                ├── incremental 
                ├── libtest.a   
                └── libtest.d   
        ```
    
        
    
    2. 准备：C函数静态链接     
        ```c
        //example.c
        #include "example.h"
        int add(int a, int b) {
            return a + b;
        }
        
        //example.h:
        #ifndef EXAMPLE_H
        #define EXAMPLE_H
        int add(int a, int b);
        #endif  // EXAMPLE_LIB_H
        ```
        编译命令：(在/C根目录下面) 编译成目标文件 libexample.o  
        `gcc -c ./example.c -o libexample.o`  
            
        将目标文件 libexample.o 打包成静态链接库    
        `ar rcs libexample.a libexample.o`
    
        那么在/c目录下有了libexample.a可以被调用
    
    3. 在rust中调用静态链接：
        1. build.rs的建立：     
           在与src文件夹平级的位置建立build.rs文件  
           指出静态链接的名称和对应的地址
           ```rust
           fn main(){
                println!("cargo:rustc-link-lib=crust");
                println!(r"cargo:rustc-link-search=native=/home/songroom/ffi/cpart");
            }
           ```
        2. Cargo.toml
           ```toml
            [package]
            name = "osh"
            version = "0.1.0"
            edition = "2021"
            build = "build.rs"
           
            #[lib]
            #name = "osh"
            #crate-type = ["staticlib"]
           
            [dependencies]
            libc = "0.2"
            [build-dependencies]
            cc = "1.0"
           ```
        3. rust代码
           ```rust
           //main.rs
           extern crate libc;
           use libc::c_int;
           
           extern "C" {
               fn add(a: c_int, b: c_int) -> c_int;
           }
           fn main() {
               println!("Hello, world!");
               let result:i32 = unsafe {
                   add(100,34)
               };
               println!("{}",result);
           }
           ```
        4. 运行cargo run得到执行结果（注意/src文件夹下面同时存在mian.rs和lib.rs程序时，代码没法正常运行，不知道原因，还待了解）


3. 在C程序中调用rust生成的静态链接
    1. rust准备      
       需要使用 extern "C" 来声明外部函数，并且使用 #[no_mangle] 来禁用 Rust 的名称修饰      
       在 Rust 中，使用`unsafe` 关键字的使用是为了标记代码块，表明其中包含的操作可能会违反 Rust 的安全性保证。Rust 语言设计的核心理念之一是内存安全和线程安全，因此它在编译时会执行严格的检查，以确保代码不会出现悬挂指针、内存泄漏、数据竞争等问题。然而，有些情况下，我们需要绕过这些检查，进行一些 Rust 不允许的操作，这就是使用 unsafe 关键字的原因。
       ```rust
       extern crate libc;
       use libc::c_int;
       extern "C" {
           fn add(a: c_int, b: c_int) -> c_int;
       }
       #[no_mangle]
       pub extern "C" fn fibonacci(n: c_int) -> c_int {
           match n {
               0 => 0,
               1 => 1,
               _ => unsafe{add(fibonacci(n - 1) , fibonacci(n - 2))},
           }
       }
       
       ```
     2. Cargo.toml
        ```toml
        [package]
        name = "search"
        version = "0.1.0"
        edition = "2021"
        build="build.rs"
        
        [lib]
        name = "search"
        crate-type = ["staticlib"]
        
        [dependencies]
        libc = "0.2"
        [build-dependencies]
        cc = "1.0"
        
        ```
     3. 使用`cargo build --release`编译Rust 项目，并在 target\release 目录下生成库文件
     4. 调用
        ```c
        //c_fact/test.c
         #include <stdio.h>
        
         extern unsigned int fibonacci(unsigned int n);
        
         int main() {
             while (1)
             {
                 int n;
                 scanf("%d",&n);
                 unsigned int result = fibonacci(n);
                 printf("Fibonacci(10) = %u\n", result);
             }
             
             
             return 0;
         }
        
        ```
        Makefile文件：
        ```Makefile
         LIB_DIR1 = ../target/release
         LIB_DIR2 = ../c
         main: main.c
             gcc -o main test.c -L$(LIB_DIR1) -L$(LIB_DIR2) -losh -lexample
         .PHONY: clean
         clean:
             rm -f ./main
        ```
        运行make指令即可生成目标文件
    
## 参考文献
https://blog.csdn.net/wowotuo/article/details/132916565

## 致谢
本项目得到了中国科学技术大学 Vlab 实验平台的帮助与支持。    
This project is accomplished with the help of Vlab Platform of University of Science and Technology of China.