## RUST与C++串并行性能测试
为了验证RUST与C++分别在串行与并行运行程序时的性能，在正式开始项目之前，我们首先对相同的简单程序在两种语言下的运行时间做了比较。以下结果均是在无任何优化编译条件下产生的。
### RUST串行程序

```RUST
// 导入必要的库
use std::time::Instant;
 
fn main() {
    // 设置迭代次数
    const ITERATIONS: u16 = 10;
 
    // 初始化计时器
    let timer = Instant::now();
 
    // 执行性能测试的代码块
    for _ in 0..ITERATIONS {
        // 放入需要测试性能的代码
         let _ = expensive_function();
    }
 
    // 计算耗时并打印结果
    let elapsed = timer.elapsed();
    println!("测试耗时：{:?}", elapsed);
}
 
// 这是一个代价较高的函数，用于演示性能测试
fn expensive_function() -> u64 {
    let mut result = 0;
    for i in 1..100_000_000 {
        result += i;
    }
    result
}
```
这段RUST代码中的 expensive_function() 完成了从1加到1亿并返回结果的功能，并且这个函数被调用了10次。以下是运行时间：
![Rust_serial](picture/RUST_serial.png)

计算平均值得到，这个程序运行时间约为1.849s
### C++串行程序

```c++
#include <time.h>
#include <stdio.h>
#include <sys/time.h>
long long expensive_function(){
	long long res=0;
	for(int i=1;i<100000000;i++){
		res+=i;
	}
	return res;
}
int main() {
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
	// 调用大开销函数
	for(int i = 0; i < 10; i++){
		expensive_function();
	}
	gettimeofday(&t2, NULL);
	
	double time = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) * 1e-6;
	printf("Time taken = %f seconds\n", time);
	
	return 0;
}
```
同样，这段C++代码中的 expensive_function() 依然是完成了与刚才RUST中函数一样的效果，并且这个函数也被调用了10次，因此两种语言所写的程序完成的任务是一致的。以下是该程序的运行时间：
![C++_serial](picture/C++_serial.png)

计算平均值得到，这个程序运行时间约为1.438s
### 小结
通过对比可以看到，在处理**简单**的串行程序方面，RUST的性能还与C++有一定差距，接下来我们来看简单的并行程序在两种语言下的表现。
### RUST并行程序
```RUST
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Instant;
 // 导入必要的库
fn expensive_function() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];
 
    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            for j in 0..10{
                *num += j;
            }
        });
        handles.push(handle);
    }
 
    for handle in handles {
        handle.join().unwrap();
    }
}
 
fn main() {
    // 设置迭代次数
    const ITERATIONS: u64 = 10000;
 
    // 初始化计时器
    let timer = Instant::now();
 
    // 执行性能测试的代码块
    for _ in 0..ITERATIONS {
         let _ = expensive_function();
    }
 
    // 计算耗时并打印结果
    let elapsed = timer.elapsed();
    println!("测试耗时：{:?}", elapsed);
}
```
这段代码中的 expensive_function() 实现了十个线程对互斥资源 num 分别累加10次的操作，在main函数中这个函数被调用了10000次，以下是运行时间：
![RUST_parallel](picture/RUST_parallel.png)

计算平均值得到，这个程序运行时间约为2.833s
### C++并行程序
```c++
#include <iostream>
#include <thread>
#include <atomic>
#include <time.h>
#include <stdio.h>
#include <sys/time.h>

std::atomic<int> counter(0); // 定义一个原子计数器

void increment() {
	for (int i = 0; i < 10; ++i) {
		counter+=i;
	}
}


int expensive_function() {
	std::thread t1(increment);
	std::thread t2(increment); 
	std::thread t3(increment);
	std::thread t4(increment);
	std::thread t5(increment);
	std::thread t6(increment);
	std::thread t7(increment);
	std::thread t8(increment);
	std::thread t9(increment);
	std::thread t10(increment);
	
	t1.join(); // 等待线程1完成
	t2.join(); // 等待线程2完成
	t3.join();
	t4.join();
	t5.join();
	t6.join();
	t7.join();
	t8.join();
	t9.join();
	t10.join();
	
	return 0;
}
int main() {
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
	// 执行你的代码
	for(int i = 0; i < 10000; i++){
		expensive_function();
	}
	gettimeofday(&t2, NULL);
	
	double time = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) * 1e-6;
	printf("Time taken = %f seconds\n", time);
	
	return 0;
}
```
这段代码与上面RUST语言写的并行代码相同，函数是十个线程对同一个互斥资源进行累加操作，并且这个函数被调用了10000次，以下是运行时间：
![C++_parellel](picture/C++_parallel.png)

 计算平均值得到，这个程序运行时间约为2.906s

 ### 小结
 可以看到，RUST在并行程序上的性能表现好于C++，说明尽管RUST在串行程序性能上没有C++优势明显，但是RUST优秀的并发特性弥补了这一点不足，使得RUST在并发性能上甚至反超了C++。