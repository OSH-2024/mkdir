// 调用c_poiner.h的reorder和decoder函数
// 实现deleteSpace(char *arr, int size);

use std::ffi::CString;
use std::os::raw::c_char;
use std::io;
use std::fs::File;
use std::io::{Read, Error};

extern "C"
{
    fn reorder(arr: *mut i32, size: i32);
}


// #[no_mangle]
// pub extern "C" fn deleteSpace(arr: *mut c_char, size: i32) {
//     let mut arr = unsafe { CString::from_raw(arr) };
//     let arr = arr.into_string().unwrap();
//     let mut arr = arr.as_bytes().to_vec();
//     let mut i = 0;
//     let mut j = 0;
//     while i < size as usize {
//         if arr[i] != 32 {
//             arr[j] = arr[i];
//             j += 1;
//         }
//         i += 1;
//     }
//     arr.resize(j, 0);
//     let arr = CString::new(arr).unwrap();
//     unsafe {
//         arr.into_raw();
//     }

//     // 创建一个int类型数组，长度为5，随机装填内容，然后调用reorder函数，最后依次打印所有内容
//     let mut arr = [1, 2, 3, 4, 5];
//     unsafe {
//         reorder(arr.as_mut_ptr(), 5);
//     }
//     for i in 0..5 {
//         println!("{}", arr[i]);
//     }
// }

// CString::from_raw在你的 deleteSpace 函数中，你使用 CString::from_raw 创建了一个 CString，这个 CString 会在离开作用域时自动释放其内部的内存。然后在 decoder 函数中，你又调用了 free(arr)，这就导致了双重释放。
// ！！！
// 方法一：创建一个返回，而不是void了
// 方法二： 直接使用 *mut c_char 指针

#[no_mangle]
pub extern "C" fn deleteSpace(arr: *mut c_char, size: i32) {
    let arr = unsafe { std::slice::from_raw_parts_mut(arr, size as usize) };
    let mut j = 0;
    for i in 0..size as usize {
        if arr[i] != 32 {
            arr[j] = arr[i];
            j += 1;
        }
    }
    for i in j..size as usize {
        arr[i] = 0;
    }
// 创建一个int类型数组，长度为50，随机装填内容，然后调用reorder函数，最后依次打印所有内容
    // let mut arr = [1, 2, 3, 4, 5];
    //读入一个整数，随机创建大小为这个的整形数组
    let mut input = String::new();
    let mut input = String::new();
    println!("请输入一个整数 n：");
    io::stdin().read_line(&mut input).expect("读取行失败");
    let n: usize = input.trim().parse().expect("解析整数失败");
    let mut array: Vec<i32> = vec![0; n];
    let mut file = match File::open("/dev/urandom") {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open /dev/urandom: {}", e);
            return;
        }
    };
    
    for i in 0..n {
        let mut buffer = [0u8; 4];
        match file.read_exact(&mut buffer) {
            Ok(_) => array[i] = i32::from_ne_bytes(buffer),
            Err(e) => {
                eprintln!("Failed to read from /dev/urandom: {}", e);
                return;
            }
        };
    }
    unsafe {
        reorder(array.as_mut_ptr(), n as i32);
    }
    
    // 不换行，加上space打印所有数字
    for i in 0..n {
        print!("{} ", array[i]);
    }
    println!();

}

// q: CString::from_raw(arr)是什么语法
// a: CString::from_raw(arr)是将arr转换为CString类型
// q: rust有指针类型吗？
// a: 有，*mut c_char就是指针类型
// q: 那么为什么不使用这种指针完成操作
// a: 因为rust不允许直接操作指针，必须使用unsafe块
// q: 举一个例子
// a: unsafe { *arr = 1; }
// q: Rust还有什么指针类型，全部列举并举例
// a: *const c_char, *mut c_char, *const i32, *mut i32
// q: C语言常见的指针类型
// a: char *, int *, void *, double *
// q: 如果rust需要构造这种指针，然后调用含这种指针的函数；或者rust接收含有这些指针的参数作为函数参数，该怎么办
// a: 使用std::ffi::CString::new(arr).unwrap().into_raw()将arr转换为指针类型
// q: 其他类型的呢
// a: 使用std::mem::transmute(arr)将arr转换为指针类型
// q: arr是i64,CString,d64可以吗
// a: 可以，只要是实现了Copy trait的类型都可以
// q: 什么是Copy trait
// a: Copy trait是一个标记trait，用于标记可以通过复制的方式传递的类型
// q: 将int *转化成rust能够操作的，加一，然后转化成int*返回。不希望使用unsafe块
// a: 使用std::mem::transmute(arr)将arr转换为指针类型

// GitHub Copilot
// 在 Rust 中，你可以使用 std::ptr::NonNull 来表示一个非空的裸指针。这是一个安全的类型，但是你仍然需要使用 unsafe 块来解引用它。然而，你可以将它转换为 Option<NonNull<T>>，这是一个完全安全的类型，你可以在不使用 unsafe 块的情况下操作它。

// 这是一个例子：
// use std::ptr::NonNull;

// fn increment_pointer(ptr: NonNull<i32>) -> NonNull<i32> {
//     let mut safe_ptr = Some(ptr);

//     // 解包 Option，得到 NonNull
//     if let Some(non_null) = safe_ptr {
//         // 使用 as_ptr 方法得到裸指针，然后使用 unsafe 块解引用它
//         unsafe {
//             *non_null.as_ptr() += 1;
//         }
//     }

//     // 重新包装为 NonNull
//     safe_ptr.unwrap()
// }
// 在这个函数中，我们接受一个 NonNull<i32>，将它转换为 Option<NonNull<i32>>，然后解包 Option，得到 NonNull。我们使用 as_ptr 方法得到裸指针，然后使用 unsafe 块解引用它并增加它的值。最后，我们重新包装 NonNull 并返回它。

// 请注意，虽然我们在这个函数中使用了 unsafe 块，但是我们确保了它的安全性，因为我们知道这个指针不是空的。

// MrUniverseCancer
// 如果是char*类型的呢？如果是结构体指针呢？

// GitHub Copilot
// 在 Rust 中，处理裸指针（如 char * 或结构体指针）的方式与处理 int * 类似。你可以使用 std::ptr::NonNull 来表示一个非空的裸指针，然后将它转换为 Option<NonNull<T>> 来安全地操作它。然而，你仍然需要使用 unsafe 块来解引用裸指针。

// 这是一个处理 char * 的例子：
// use std::ptr::NonNull;

// fn increment_char_pointer(ptr: NonNull<char>) -> NonNull<char> {
//     let mut safe_ptr = Some(ptr);

//     if let Some(non_null) = safe_ptr {
//         unsafe {
//             let value = *non_null.as_ptr() as u8 + 1;
//             *non_null.as_ptr() = value as char;
//         }
//     }

//     safe_ptr.unwrap()
// }
// 这是一个处理结构体指针的例子：
// use std::ptr::NonNull;

// struct MyStruct {
//     value: i32,
// }

// fn increment_struct_pointer(ptr: NonNull<MyStruct>) -> NonNull<MyStruct> {
//     let mut safe_ptr = Some(ptr);

//     if let Some(non_null) = safe_ptr {
//         unsafe {
//             (*non_null.as_ptr()).value += 1;
//         }
//     }

//     safe_ptr.unwrap()
// }