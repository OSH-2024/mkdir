## 项目改写进度
**(示例：潘铂凯：改写xxx函数模块，xxx行-xxx行)**

胡揚嘉：改写200-220行的bpf_probe_read_user_str_common函数 <br>
潘铂凯：改写361-371行的bpf_get_probe_write_proto函数 <br>
潘铂凯：改写111-156行的trace_call_bpf函数 <br>
潘铂凯：改写1168-1175行的BPF_CALL_1函数 <br>
潘铂凯：改写908-936行的BPF_CALL_3函数 <br>
潘铂凯：改写372-398行的BPF_CALL_5函数 <br>
潘铂凯：改写761-776行的BPF_CALL_0函数 <br>
刘宇恒：改写BPF_CALL_2这一宏（先转化成Rust形式，指针问题尚未处理） <br>
潘铂凯：改写252-277行的bpf_probe_read_kernel_str_common函数 <br>
王翔辉：改写399-405行的bpf_func_proto 部分 <br>
王翔辉：改写407-420行的_set_printk_clr_event函数 <br>
金培晟：改写842-882行的bpf_send_signal_common函数 <br>
潘铂凯：改写174-190行的bpf_probe_read_user_common & BPF_CALL_3函数 <br>
胡揚嘉：改写1052-1062行get_entry_ip函数


## 现已完成代码段汇总
**（请按顺序填写）** <br>
111-156 <br>
174-190 <br>
200-220 <br>
252-277 <br>
361-371 <br>
372-398 <br>
399-405 <br>
407-420 <br>
761-776 <br>
842-882 <br>
908-936 <br>
1052-1052<br>
1168-1175 <br>


## 小组工作交流栏
**（请不要删除，保留交流历史记录）** <br>
**（示例：潘铂凯：我在改写xxx模块时遇到了问题，已经放到了我的改写文件夹中，希望大家能够帮忙分析一下改写思路）** <br>
潘铂凯：大家快把存货端出来，小步快跑ヾ(≧▽≦*)o <br>
金培晟：我在改写bpf_send_signal模块的测试时遇到问题，可能是一些宏和引用无效导致的。 <br>
胡揚嘉：宏怎么修改和使用？需要找到原始的宏来决定怎么修改代码。指针的问题还需要讨论。结构体先定义一下，bpf_func_proto反复使用。
<br>
