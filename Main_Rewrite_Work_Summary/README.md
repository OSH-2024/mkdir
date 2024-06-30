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
胡揚嘉：改写1052-1062行get_entry_ip函数 <br>
胡揚嘉：改写1779-1792行tp_prog_is_valid_access函数 <br>
王翔辉：改写421-425行的 BpfFuncProto 部分 <br>
潘铂凯：改写1828-1855行的BPF_CALL_4函数 <br>
刘宇恒：改写407-419行的__set_printk_clr_event<br>
潘铂凯：改写1856-1886行的pe_prog_func_proto<br>
潘铂凯：改写1991-2015行的raw_tp_prog_func_proto<br>
潘铂凯：改写2125-2137行的raw_tp_writable_prog_is_valid_access<br>
潘铂凯：改写2082-2089行的raw_tp_prog_is_valid_access<br>
潘铂凯：改写2090-2097行的tracing_prog_is_valid_access<br>
潘铂凯：改写2146-2183行的pe_prog_is_valid_access_access<br>
潘铂凯：改写2884-2894行的has_module<br>
潘铂凯：改写2934-2944行的addrs_check_error_injection_list<br>
潘铂凯：改写2895-2933行的get_modules_for_addrs<br>
潘铂凯：改写2945-3086行的bpf_kprobe_multi_link_attach<br>
潘铂凯：改写2844-2860行的symbols_swap_r<br>
潘铂凯：改写3159-3227行的bpf_uprobe_multi_link_fill_link_info<br>
王翔辉：改写426-452 行的bpf_trace_vprintk 部分 <br>
王翔辉：改写454-535 行的函数定义结构体定义部分 <br>
王翔辉：改写537-546 行的结构体定义部分 <br>
胡揚嘉：改写3458-3469行的bpf_uprobe_multi_函数部分  <br>
胡揚嘉：改写3315-3456行的bpf_uprobe_multi_link_attach函数部分  <br>
王翔辉：改写548-609 行的get_map_perf_counter等部分 <br>
王翔辉：改写610-654 bpf_perf_event_read_value_proto结构体 __bpf_perf_event_output函数 <br>
胡揚嘉：改写3228-3314行的函数部分  <br>
潘铂凯：改写1504-1635行的bpf_tracing_func_proto<br>
胡揚嘉：改写2432-2577行的相关函数部分  <br>

## 现已完成代码段汇总
**（请按顺序填写）** <br>
111-156 <br>
174-190 <br>
200-220 <br>
252-277 <br>
361-371 <br>
372-398 <br>
399-405 <br>
407-419（改重了）<br>
407-420 <br>
421-452 <br>
454-535 <br>
537-546 <br>
548-609 <br>
610-654 <br>
761-776 <br>
842-882 <br>
908-936 <br>
1052-1052<br>
1168-1175 <br>
1504-1635<br>
1779-1792<br>
1828-1855<br>
1856-1886<br>
1991-2015<br>
2082-2089<br>
2090-2097<br>
2125-2137<br>
2146-2183<br>
2432-2577<br>
2844-2860<br>
2884-2894<br>
2895-2933<br>
2934-2944<br>
2945-3086<br>
3159-3227<br>
3228-3314<br>
3315-3456<br>
3458-3469<br>



## 小组工作交流栏
**（请不要删除，保留交流历史记录）** <br>
**（示例：潘铂凯：我在改写xxx模块时遇到了问题，已经放到了我的改写文件夹中，希望大家能够帮忙分析一下改写思路）** <br>
潘铂凯：大家快把存货端出来，小步快跑ヾ(≧▽≦*)o <br>
金培晟：我在改写bpf_send_signal模块的测试时遇到问题，可能是一些宏和引用无效导致的。 <br>
胡揚嘉：宏怎么修改和使用？需要找到原始的宏来决定怎么修改代码。指针的问题还需要讨论。结构体先定义一下，bpf_func_proto反复使用。<br>
潘铂凯：大家在改写模块前记得看一下README，不要改重了<br>

