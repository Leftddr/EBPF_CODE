from collections import defaultdict

class ebpfCode :
    def __init__(self, func_name) :
        self.kernel_func_name = func_name
        self.attach_func_name = []
        for func_name in self.kernel_func_name:
            if func_name.find("sock") != -1:
                self.attach_func_name.append("kprobe__" + func_name)
                self.attach_func_name.append("kretprobe__" + func_name)
            else :
                self.attach_func_name.append("kprobe__" + func_name)
    ##############################################
    # we need default function to usage 
    ##############################################
    def erase_slacks(self, prog) :
        prog = prog.split('\\')
        prog = ' '.join(prog)
        return prog
    
    def set_header_file(self) :
        return r'\
            #include <linux/net.h>\
            #include <linux/netdevice.h>\
            #include <linux/sched.h>\
            #include <net/dst.h>\
            #include <net/sock.h>\
            #include <uapi/linux/bpf.h>\
            #include <uapi/linux/ptrace.h>\
            #define EVENT_BATCH 10'
    ################################################
    # What we need ? #
    # src_addr, dst_addr, src_port, dst_port, ts # common part
    # for ovs : sent_bytes # 
    # for other server kvm : seq_num # different part # 100bytes => 33, 33, 33 bytes 
    # but we neet to occur event both of them because packet transmit or receive in here just packet change. #
    # in python, we will differentate the different part #
    ################################################
    def set_event_data_type(self) :
        return r'\
            struct data_t_info {\
                u32 src_addr, dst_addr;\
                u16 src_port, dst_port;\
                u64 ts;\
                u64 sent_bytes; \
                u32 seq_num; \
                u32 evt_type; \
                u64 e_count; \
            }; \
            struct ovs_flow_info {\
                u32 src_addr, dst_addr;\
            };\
            struct kvm_flow_info {\
                u32 src_addr, dst_addr;\
                u16 src_port, dst_port;\
            };\
            struct event_batch {\
                struct data_t_info arr[EVENT_BATCH];\
            };'
    
    def set_event(self) :
        return r'\
            BPF_RINGBUF_OUTPUT(events, 1024);'
    
    def set_map(self) :
        return r'\
            BPF_HASH(ovs_sum_pkt_len, struct ovs_flow_info); \
            BPF_HASH(kvm_sum_pkt_len, struct kvm_flow_info); \
            BPF_HASH(index_for_ovs_flow_info, struct ovs_flow_info);\
            BPF_ARRAY(event_array, struct data_t_info, 64);\
            BPF_HASH(tx_ts, u64);\
            BPF_HASH(rx_ts, u64);\
            BPF_HASH(tx_count, u64);\
            BPF_HASH(rx_count, u64);\
            BPF_HASH(tx_seq, struct kvm_flow_info, u32);\
            BPF_HASH(rx_seq, struct kvm_flow_info, u32);'

    def common_using_func(self) :
        return r'\
            static inline void network_header_read(void *network_header, u8 ip_header[20]) {\
	            bpf_probe_read_kernel(&ip_header[0], 20, network_header);\
            }\
            \
            static inline s32 tcp_header_to_header_length(void *transport_header) {\
                u8 tcp_data_offset = 0;\
                u8 tcp_header_length = 0;\
                bpf_probe_read_kernel(&tcp_data_offset, 1, transport_header + 12);\
                tcp_header_length = ((tcp_data_offset >> 4) << 2);\
                return tcp_header_length;\
            }\
            \
            static inline void* sk_buff_to_network_header_low_layer(struct sk_buff *skb) {\
                return skb->data;\
            }\
            \
            static inline void* sk_buff_to_network_header(struct sk_buff *skb) {\
                void *skb_data = skb->head;\
                u16 network_header = 0;\
                bpf_probe_read_kernel(&network_header, sizeof(network_header), &(skb->network_header));\
                return skb->head + skb->network_header;\
            }\
            \
            static inline s32 network_header_to_data_len(void *network_header, u8 ip_header[20]) {\
                void *transport_header = NULL;\
                s32 ip_data_len = 0;\
                u8 ihl = 0;\
                \
                ihl = ((ip_header[0] & 15) << 2);\
                ip_data_len = ((ip_header[2] << 8) | (ip_header[3]));\
                \
                transport_header = network_header + ihl;\
                \
                return ip_data_len - ihl - tcp_header_to_header_length(transport_header);\
            }\
            \
            static inline void* network_header_to_transport_header(void *network_header, u8 ip_header[20]) {\
                u8 ihl = 0;\
                network_header_read(network_header, ip_header);\
                if ((ip_header[0] >> 4) != 4)\
                    return NULL; // Not ipv4\
                if (ip_header[9] != 6)\
                    return NULL; // Not TCP\
                ihl = ((ip_header[0] & 15) << 2);\
                \
                return network_header + ihl;\
            }\
            \
            static inline void output_queue_ringbuf(){\
                struct event_batch *res = events.ringbuf_reserve(sizeof(struct event_batch));\
                if(res == NULL) return;\
                bpf_trace_printk("ok here");\
                \
                for(u32 i = 0 ; i < EVENT_BATCH ; i++) {\
                    struct data_t_info *data = NULL;\
                    u32 key = i;\
                    \
                    data = event_array.lookup(&key);\
                    if(data == NULL) continue; \
                    \
                    bpf_probe_read_kernel(&(res->arr[i]), sizeof(struct data_t_info), data);\
                    //events.ringbuf_submit(data, 0);\
                }\
                bpf_trace_printk("submit");\
                events.ringbuf_submit(res, 0);\
            }'
            
    
    def func_common_head_part(self, func_name) :
        return 'int ' + func_name + '(struct pt_regs *ctx){'
    
    def func_common_end_part(self) :
        return r'return 0;}'

    def func_set_ovs_data_part(self) :
        return r'\
            data_ovs.src_addr = src_addr, data_ovs.dst_addr = dst_addr;\
            data_ovs.src_port = src_port, data_ovs.dst_port = dst_port;\
            data_ovs.ts = *ovs_ts;\
            data_ovs.sent_bytes = *sent_bytes_ovs, data_ovs.seq_num = 0;\
            data_ovs.evt_type = #what_type#, data_ovs.e_count = *cur_cnt;'

    def func_set_kvm_data_part(self) : 
        return r'\
            data_kvm.src_addr = src_addr, data_kvm.dst_addr = dst_addr;\
            data_kvm.src_port = src_port, data_kvm.dst_port = dst_port;\
            data_kvm.ts = *kvm_ts;\
            data_kvm.sent_bytes = *sent_bytes_kvm, data_kvm.seq_num = seq;\
            data_kvm.evt_type = #what_type#, data_kvm.e_count = *cur_cnt;'

    ##############################################
    # We use this func where not receive argument of struct sk_buff #
    # sock_sendmsg, inet_sengmsg #
    ##############################################
    def sock_func_enter_head_part(self) :
        return r'\
            u64 pid = bpf_get_current_pid_tgid();\
            u64 cur_ts = bpf_ktime_get_boot_ns();\
            #which_ts#.update(&pid, &cur_ts);'

    def sock_func_exit_head_part(self) :
        return r'\
            struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);\
            u64 pid = bpf_get_current_pid_tgid(), *cur_ts = #which_ts#.lookup(&pid);\
            if(cur_ts == NULL) return 0;\
            u32 src_addr, dst_addr, zero = 0;\
            u16 src_port = 0, dst_port = 0;\
            u64 *cur_cnt = #which_count#.lookup_or_try_init(&pid, (u64*)&zero);\
            if(cur_cnt == NULL) return 0;\
            u64 *ovs_ts = cur_ts, *kvm_ts = cur_ts;\
            s32 len = PT_REGS_RC(ctx);\
            \
            bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);\
            bpf_probe_read_kernel(&src_port, sizeof(src_port), &sk->__sk_common.skc_num);\
            src_addr = sk->__sk_common.skc_rcv_saddr;\
            dst_addr = sk->__sk_common.skc_daddr;\
            //bpf_probe_read_kernel(&src_addr, sizeof(src_addr), &sk->__sk_common.skc_rcv_saddr);\
            //bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &sk->__sk_common.skc_daddr);\
            dst_port = (((dst_port << 8) | (dst_port >> 8)));'
    
    def sock_func_exit_fill_data_part(self) :
        part = ''
        part += self.ip_func_make_key_part()
        
        part += r'\
            u32 *seq_ = #what_seq#.lookup(&kvm_fi);\
            if(seq_ == NULL) return 0;\
            u32 seq = *seq_;\
            u64 *sent_bytes_ovs = #ovs_pkt_len#.lookup_or_try_init(&ovs_fi, (u64*)&zero);\
            if(sent_bytes_ovs == NULL) return 0;\
            u64 *sent_bytes_kvm = #kvm_pkt_len#.lookup_or_try_init(&kvm_fi, (u64*)&zero);\
            if(sent_bytes_kvm == NULL) return 0;\
            struct data_t_info data_ovs = {};\
            struct data_t_info data_kvm = {};'
        
        part += self.func_set_ovs_data_part();
        part += self.func_set_kvm_data_part();
        return part

    # 이미 ip function 부분에서 pkt_len을 update해서 올라온다.
    def sock_func_exit_update_data_part(self) :
        return r'\
            *cur_cnt += 1;\
            #which_count#.update(&pid, cur_cnt);'

    def sock_func_exit_determine_occur_event(self) :
        return self.ip_send_func_determine_occur_event()
    
    #############################################
    # We use this func where receive argument of sturct sk_buff *skb to parsing src_addr, dst_addr, lport, rport #
    # __ip_queue_xmit, dev_queue_xmit #
    #############################################
    def ip_func_common_head_part(self) :
        return r'\
            struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);\
            u64 cur_ts = bpf_ktime_get_boot_ns(), pid = bpf_get_current_pid_tgid();\
            struct data_t_info data = {};\
            u8 header[8];\
            u16 src_port = 0, dst_port = 0;\
            u32 seq;\
            u64 zero = 0;\
            s32 len;\
            u64 *cur_cnt = #which_count#.lookup_or_try_init(&pid, &zero);\
            if(cur_cnt == NULL) return 0;\
            \
            u8 ip_header[20];\
            void *network_header = sk_buff_to_network_header(skb);\
            void *headerp = network_header_to_transport_header(network_header, ip_header);\
            if(headerp == NULL) return 0;\
            headerp = skb->head + skb->transport_header;\
            bpf_probe_read_kernel(&header, sizeof(header), headerp);\
            len = network_header_to_data_len(network_header, ip_header);\
            if(len < 0) return 0;'
    
    def ip_func_common_port_part(self) :
        return r'\
            dst_port = ((header[2] << 8) | header[3]);\
            src_port = ((header[0] << 8) | header[1]);\
            seq = ((header[4] << 24) | (header[5] << 16) | (header[6] << 8) | header[7]);\
            u32 portpair = ((dst_port << 16) | src_port);'
    
    def ip_func_common_ip_part(self) :
        return r'\
            u32 src_addr = ((ip_header[12] << 24) | (ip_header[13] << 16) | (ip_header[14] << 8) | ip_header[15]);\
            u32 dst_addr = ((ip_header[16] << 24) | (ip_header[17] << 16) | (ip_header[18] << 8) | ip_header[19]);'
    #############################################################################
    # Here we calculate sum_pkt_len for ovs #
    # And kvm can calculate how much they sent packets to each other kvm. #
    #############################################################################
    def ip_func_make_key_part(self) :
        return r'\
            struct ovs_flow_info ovs_fi = {};\
            ovs_fi.src_addr = src_addr, ovs_fi.dst_addr = dst_addr;\
            struct kvm_flow_info kvm_fi = {};\
            kvm_fi.src_addr = src_addr, kvm_fi.dst_addr = dst_addr;\
            kvm_fi.src_port = src_port, kvm_fi.dst_port = dst_port;'

    def ip_func_calc_sent_bytes(self):
        return r'\
            u64 *sent_bytes_ovs = #ovs_pkt_len#.lookup_or_try_init(&ovs_fi, (u64*)&zero);\
            if(sent_bytes_ovs == NULL) return 0;\
            else *sent_bytes_ovs += len;\
            #ovs_pkt_len#.update(&ovs_fi, sent_bytes_ovs);\
            \
            u64 *sent_bytes_kvm = #kvm_pkt_len#.lookup_or_try_init(&kvm_fi, (u64*)&zero);\
            if(sent_bytes_kvm == NULL) return 0;\
            else *sent_bytes_kvm += len;\
            #kvm_pkt_len#.update(&kvm_fi, sent_bytes_kvm);'

    def ip_send_func_fill_data_part(self) :
        return r'\
            #what_seq#.update(&kvm_fi, &seq);\
            u64 ovs_ts_ = bpf_ktime_get_boot_ns();\
            u64 *ovs_ts = &ovs_ts_;\
            u64 kvm_ts_ = bpf_ktime_get_boot_ns();\
            u64 *kvm_ts = &kvm_ts_;\
            \
            struct data_t_info data_ovs = {};\
            struct data_t_info data_kvm = {};'
    
    def ip_send_func_determine_occur_event(self) :
        return r'\
            u64 *index = index_for_ovs_flow_info.lookup(&ovs_fi);\
            if(index == NULL) {\
                index_for_ovs_flow_info.update(&ovs_fi, (u64*)&zero);\
                return 0;\
            }\
            \
            if(*index + 2 < EVENT_BATCH) {\
                event_array.update((int*)index, &data_ovs);\
                *index += 1;\
                event_array.update((int*)index, &data_kvm);\
                *index += 1;\
                index_for_ovs_flow_info.update(&ovs_fi, index);\
                u64 *tmp_index = index_for_ovs_flow_info.lookup(&ovs_fi);\
                if(tmp_index == NULL) return 0;\
            }\
            else {\
                output_queue_ringbuf();\
                *index = 0;\
                event_array.update((int*)index, &data_ovs);\
                *index = 1;\
                event_array.update((int*)index, &data_kvm);\
                index_for_ovs_flow_info.update(&ovs_fi, index);\
            }'

    ###############################################################################
    # This is temp version because sock_* function cannot be catched now...
    ###############################################################################
    
    def ip_func_update_data(self):
        return r'\
            *cur_cnt += 1;\
            #which_count#.update(&pid, cur_cnt);'

    ###############################################################################
    # Other default func to help function make. #
    ###############################################################################
    def replace_sentence(self, func, find_sentence, change_sentence):
        func = func.replace(find_sentence, change_sentence)
        return func
    ###############################################################################
    # here we start to attach function #
    # sock_sengmsg, dev_queue_xmit
    # sock_recvmsg, ip_rcv_core
    ###############################################################################
    def attach_function(self) :
        prog = ''
        for idx, func_name in enumerate(self.attach_func_name):
            print(func_name)
            func = self.func_common_head_part(func_name)
            if func_name.find("kprobe") != -1 and func_name.find("sock") != -1:
                func += self.sock_func_enter_head_part()
            else :
                if func_name.find("sock") != -1:
                    func += self.sock_func_exit_head_part()
                    func += self.sock_func_exit_fill_data_part()
                    func += self.sock_func_exit_determine_occur_event()
		    #func += self.sock_func_exit_update_data_part()
                else :
                    func += self.ip_func_common_head_part()
                    func += self.ip_func_common_ip_part()
                    func += self.ip_func_common_port_part()
                    func += self.ip_func_make_key_part()
                    func += self.ip_func_calc_sent_bytes()
                    func += self.ip_send_func_fill_data_part()
                    func += self.func_set_ovs_data_part()
                    func += self.func_set_kvm_data_part()
                    func += self.ip_send_func_determine_occur_event()
                    func += self.ip_func_update_data()
                
            if func_name.find("send") != -1 or func_name.find("queue") != -1:
                func = self.replace_sentence(func, "#which_count#", "tx_count")
                func = self.replace_sentence(func, "#which_ts#", "tx_ts")
            else :
                func = self.replace_sentence(func, "#which_count#", "rx_count")
                func = self.replace_sentence(func, "#which_ts#", "rx_ts")
            func = self.replace_sentence(func, "#ovs_pkt_len#", "ovs_sum_pkt_len")
            func = self.replace_sentence(func, "#kvm_pkt_len#", "kvm_sum_pkt_len")
            func = self.replace_sentence(func, "#what_type#", str(idx))
            if func_name.find("send") != -1 or func_name.find("queue") != -1 :
                func = self.replace_sentence(func, "#what_seq#", "tx_seq")
            else :
                func = self.replace_sentence(func, "#what_seq#", "rx_seq")
            func += self.func_common_end_part()
            prog += func
        return prog

    def make_complete_code(self) :
        prog = self.set_header_file()
        prog += self.set_event_data_type()
        prog += self.set_event()
        prog += self.set_map()
        prog += self.common_using_func()
        prog += self.attach_function()
        prog = self.erase_slacks(prog)
        fp = open('code.txt' ,'w')
        fp.write(prog)
        fp.close()
        return prog
