from collections import defaultdict

class ebpfCode :
    ############################################################################
    # we only set function name and change function name to event function name.
    # what we need function?
    # virtio_dev_tx_split_exit, virtio_dev_tx_packed_exit, mlx5_tx_burst_none_empw
    # virtio_dev_rx_split_enter, virtio_dev_rx_packed_enter, mlx5_rx_burst_vec_exit
    ############################################################################
    def __init__(self):
        self.ovs_func_name = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "mlx5_tx_burst_none_empw", "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec"]
        #self.ovs_func_name = ["mlx5_rx_burst_vec", "virtio_dev_rx_split"]
    def set_header(self):
        return r'\
            #include <linux/sched.h>\
            #include <uapi/linux/ptrace.h>\
            #include <uapi/linux/bpf.h>\
            #include "include/mbuf.h"\
            #include "include/packet.h"\
            #define PACKET_PARSE 32\
            #define EVENT_BATCH 10\
            #define ETHER_TYPE 8\
            #define IPV4_TYPE 4\
            #define TCP_TYPE 6'

    def set_event_data_type(self) :
        return r'\
            struct data_type {\
                u32 src_addr, dst_addr;\
                u16 src_port, dst_port;\
                u32 pid;\
                u64 ts;\
                u64 pkt_len;\
                u64 e_count;\
                u32 sent_seq, recv_ack;\
                u8 evt_type;\
            };\
            struct event_type {\
                struct data_type arr[EVENT_BATCH];\
            };\
            struct flow_info {\
                u32 src_addr, dst_addr;\
                u32 src_port, dst_port;\
            };'
  
    def set_event(self):
        return r'\
            BPF_RINGBUF_OUTPUT(virtio_dev_tx_ringbuf, 1024);\
            BPF_RINGBUF_OUTPUT(mlx5_tx_burst_ringbuf, 1024);\
            BPF_RINGBUF_OUTPUT(virtio_dev_rx_ringbuf, 1024);\
            BPF_RINGBUF_OUTPUT(mlx5_rx_burst_ringbuf, 1024);'

    def set_map(self):
        return r'\
            BPF_HASH(tx_poll_count, u32);\
            BPF_HASH(rx_poll_count, u32);\
            BPF_QUEUE(virtio_dev_tx_queue, struct data_type, 10240); \
            BPF_QUEUE(mlx5_tx_burst_queue, struct data_type, 10240); \
            BPF_QUEUE(virtio_dev_rx_queue, struct data_type, 10240); \
            BPF_QUEUE(mlx5_rx_burst_queue, struct data_type, 10240); \
            BPF_ARRAY(virtio_dev_tx_array, struct data_type, 64); \
            BPF_ARRAY(mlx5_tx_burst_array, struct data_type, 64); \
            BPF_ARRAY(virtio_dev_rx_array, struct data_type, 64); \
            BPF_ARRAY(mlx5_rx_burst_array, struct data_type, 64); \
            BPF_HASH(virtio_dev_tx_index, struct flow_info, u32); \
            BPF_HASH(mlx5_tx_burst_index, struct flow_info, u32); \
            BPF_HASH(virtio_dev_rx_index, struct flow_info, u32); \
            BPF_HASH(mlx5_rx_burst_index, struct flow_info, u32); \
            BPF_HASH(virtio_dev_tx_pkt_len, struct flow_info); \
            BPF_HASH(mlx5_tx_burst_pkt_len, struct flow_info); \
            BPF_HASH(virtio_dev_rx_pkt_len, struct flow_info); \
            BPF_HASH(mlx5_rx_burst_pkt_len, struct flow_info); \
            BPF_HASH(virtio_dev_tx_used, struct flow_info, u8); \
            BPF_HASH(mlx5_tx_burst_used, struct flow_info, u8); \
            BPF_HASH(virtio_dev_rx_used, struct flow_info, u8); \
            BPF_HASH(mlx5_rx_burst_used, struct flow_info, u8);'
        
    #####################################################################
    # common function part (start, end)
    #####################################################################

    def function_start(self, func_name) :
        return func_name + "(struct pt_regs *ctx){"
    
    def function_end(self):
        return r'return  0;}'
    ########################################################################
    # common using funcion which define 'static inline'
    ########################################################################
    def erase_slacks(self, prog) :
        prog = prog.split('\\')
        return ' '.join(prog)
    
    def replace_sentence(self, func, from_sentence, to_sentence) :
        return func.replace(from_sentence, to_sentence)
    
    def which_queue_use(self, func_name) :
        if func_name.find("virtio_dev_tx") != -1 : return "0"
        elif func_name.find("mlx5_tx") != -1 : return "1"
        elif func_name.find("virtio_dev_rx") != -1 : return "2"
        else : return "3"
    
    def param_pos(self, func_name) :
        if func_name.find("mlx5") != -1 : return "PT_REGS_PARM2"
        else : return "PT_REGS_PARM4"

    def common_using_func(self) :
        return r'\
            static inline void output_queue(int which_queue) {\
                struct event_type event = {};\
                for(u32 i = 0 ; i < EVENT_BATCH ; i++) {\
                    struct data_type *data = NULL;\
                    u32 key = i;\
                    if(which_queue == 0) data = virtio_dev_tx_array.lookup(&key);\
                    else if(which_queue == 1) data = mlx5_tx_burst_array.lookup(&key);\
                    else if(which_queue == 2) data = virtio_dev_rx_array.lookup(&key);\
                    else data = mlx5_rx_burst_array.lookup(&key);\
                    if(data == NULL) continue;\
                    \
                    if(which_queue == 0) virtio_dev_tx_queue.push(data, BPF_EXIST);\
                    else if(which_queue == 1) mlx5_tx_burst_queue.push(data, BPF_EXIST);\
                    else if(which_queue == 2) virtio_dev_rx_queue.push(data, BPF_EXIST);\
                    else mlx5_rx_burst_queue.push(data, BPF_EXIST);\
                   // bpf_probe_read_kernel(&(event.arr[i]), sizeof(struct data_type), data);\
                }\
                //if(which_queue == 0) virtio_dev_tx_queue.push(&event, BPF_EXIST);\
                //else if(which_queue == 1) mlx5_tx_burst_queue.push(&event, BPF_EXIST);\
                //else if(which_queue == 2) virtio_dev_rx_queue.push(&event, BPF_EXIST);\
                //else mlx5_rx_burst_queue.push(&event, BPF_EXIST);\
            }'

    def common_using_func_ringbuf(self) :
        return r'\
            static inline void output_queue(int which_ringbuf){\
                struct event_type *event;\
                if(which_ringbuf == 0) event = virtio_dev_tx_ringbuf.ringbuf_reserve(sizeof(struct event_type));\
                else if(which_ringbuf == 1) event = mlx5_tx_burst_ringbuf.ringbuf_reserve(sizeof(struct event_type));\
                else if(which_ringbuf == 2) event = virtio_dev_rx_ringbuf.ringbuf_reserve(sizeof(struct event_type));\
                else event = mlx5_rx_burst_ringbuf.ringbuf_reserve(sizeof(struct event_type));\
                if(event == NULL) return;\
                \
                for(u32 i = 0 ; i < EVENT_BATCH ; i++){\
                    struct data_type *data = NULL;\
                    u32 key = i;\
                    if(which_ringbuf == 0) data = virtio_dev_tx_array.lookup(&key);\
                    else if(which_ringbuf == 1) data = mlx5_tx_burst_array.lookup(&key);\
                    else if(which_ringbuf == 2) data = virtio_dev_rx_array.lookup(&key);\
                    else data = mlx5_rx_burst_array.lookup(&key);\
                    if(data == NULL) continue;\
                    bpf_probe_read_kernel(&(event->arr[i]), sizeof(struct data_type), data);\
                }\
                if(which_ringbuf == 0) virtio_dev_tx_ringbuf.ringbuf_submit(event, 0);\
                else if(which_ringbuf == 1) mlx5_tx_burst_ringbuf.ringbuf_submit(event, 0);\
                else if(which_ringbuf == 2) virtio_dev_rx_ringbuf.ringbuf_submit(event, 0);\
                else mlx5_rx_burst_ringbuf.ringbuf_submit(event, 0);\
            }'
    #######################################################################
    # packet parsing function part
    #######################################################################
    def set_val_part(self) :
        return r'\
            u32 pid = bpf_get_current_pid_tgid();\
            u64 zero = 0, one = 1;\
            u64 *e_count = #poll_count#.lookup_or_try_init(&pid, &zero);\
            if(e_count == NULL) return 0;\
            struct rte_mbuf **pkts = (struct rte_mbuf**)#param_position#(ctx);\
            s32 pkt_cnt = PT_REGS_RC(ctx);\
            if(!pkt_cnt) return 0;\
            union {\
                struct rte_ether_hdr *eth;\
                struct rte_vlan_hdr *vlan;\
                struct rte_ipv4_hdr *ipv4;\
                struct rte_ipv6_hdr *ipv6;\
                struct rte_tcp_hdr *tcp;\
                struct rte_udp_hdr *udp;\
                uint8_t *byte;\
            }h;'
    
    def extract_from_packet_part(self):
        return r'\
            u64 *pkt_len = #which_pkt_len#.lookup_or_try_init(&fi, &zero);\
            if(pkt_len == NULL) continue;\
            u8 *used = #which_used#.lookup_or_try_init(&fi, (u8*)&zero);\
            if(used == NULL) continue; \
            *pkt_len += mbuf->pkt_len;\
            #which_pkt_len#.update(&fi, pkt_len);\
            #which_used#.update(&fi, (u8*)&one);'
    
    def parse_packet_part(self) :
        return r'\
            for(int i = 0 ; i < PACKET_PARSE ; i++) {\
                if(pkt_cnt > 0 && i >= pkt_cnt) break;\
                struct rte_mbuf *mbuf = pkts[i];\
                if(mbuf == 0x0) break;\
                \
                h.eth = (struct rte_ether_hdr *)((char *)mbuf->buf_addr + mbuf->data_off);\
                u16 proto = h.eth->ether_type;\
                struct rte_ether_hdr eth_hdr;\
                struct rte_ipv4_hdr ipv4_hdr;\
                struct rte_tcp_hdr tcp_hdr;\
                bpf_probe_read_kernel(&eth_hdr, sizeof(struct rte_ether_hdr), h.eth);\
                \
                int limit_cnt = 0;\
                while (limit_cnt < PACKET_PARSE && (proto == RTE_BE16(RTE_ETHER_TYPE_VLAN) || proto == RTE_BE16(RTE_ETHER_TYPE_QINQ))) {\
                    struct rte_vlan_hdr vlan_hdr;\
                    bpf_probe_read_kernel(&vlan_hdr, sizeof(struct rte_vlan_hdr), (h.vlan + limit_cnt));\
                    proto = vlan_hdr.eth_proto;\
                    limit_cnt++;\
                }\
                \
                bpf_probe_read_kernel(&ipv4_hdr, sizeof(struct rte_ipv4_hdr), h.ipv4);\
                bpf_trace_printk("src_addr = %u, dst_addr = %u", ipv4_hdr.src_addr, ipv4_hdr.dst_addr);\
                u16 next_proto = ipv4_hdr.next_proto_id;\
                bpf_trace_printk("next_proto = %u", next_proto);\
                //if(next_proto != IPPROTO_TCP); continue;\
                bpf_probe_read_kernel(&tcp_hdr, sizeof(struct rte_tcp_hdr), h.tcp);\
                bpf_trace_printk("src_addr = %u, dst_addr = %u", ipv4_hdr.src_addr, ipv4_hdr.dst_addr);\
                bpf_trace_printk("src_port = %u, dst_port = %u, seq_num = %d", tcp_hdr.src_port, tcp_hdr.dst_port, tcp_hdr.sent_seq);\
                struct flow_info fi = {};\
                #what_code_insert#\
            }'
    
    def parse_packet_new_part(self) :
        return r'\
            for(int i = 0 ; i < PACKET_PARSE ; i++) {\
                if(pkt_cnt > 0 && i >= pkt_cnt) break;\
                struct rte_mbuf *mbuf = pkts[i];\
                if(mbuf == 0x0) break;\
                struct rte_ether_hdr eth_hdr;\
                struct rte_ipv4_hdr ip_hdr;\
                struct rte_tcp_hdr tcp_hdr;\
                char *ether_hdr = mbuf->buf_addr + mbuf->data_off;\
                bpf_probe_read(&eth_hdr, (size_t)sizeof(eth_hdr), ether_hdr);\
                u16 proto = eth_hdr.ether_type;\
                if(proto != ETHER_TYPE) continue;\
                bpf_probe_read(&ip_hdr, (size_t)sizeof(ip_hdr), ether_hdr + sizeof(struct rte_ether_hdr));\
                if((ip_hdr.version_ihl >> 4) != IPV4_TYPE) continue;\
                proto = ip_hdr.next_proto_id;\
                if(proto != TCP_TYPE) continue;\
                bpf_probe_read(&tcp_hdr, (size_t)sizeof(tcp_hdr), ether_hdr + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));\
                struct flow_info fi = {ip_hdr.src_addr, ip_hdr.dst_addr, tcp_hdr.src_port, tcp_hdr.dst_port};\
                #what_code_insert#\
            }'
    
    def occur_event_part(self) :
        return r'\
            u8 *used = #which_used#.lookup(&fi);\
            if(used == NULL || *used == 0) continue; \
            u64 *pkt_len = #which_pkt_len#.lookup(&fi); \
            if(pkt_len == NULL) continue;\
            u32 *array_index = #which_array_index#.lookup_or_try_init(&fi, (u32*)&zero);\
            if(array_index == NULL) continue; \
            struct data_type data = {};\
            data.src_addr = ip_hdr.src_addr, data.dst_addr = ip_hdr.dst_addr;\
            data.src_port = tcp_hdr.src_port, data.dst_port = tcp_hdr.dst_port;\
            data.pid = pid;\
            data.ts = bpf_ktime_get_boot_ns();\
            data.pkt_len = *pkt_len, data.e_count = *e_count;\
            data.sent_seq = tcp_hdr.sent_seq, data.recv_ack = tcp_hdr.recv_ack;\
            data.evt_type = #what_evt_type#;\
            #which_array#.update(array_index, &data);\
            \
            (*array_index)++;\
            if(*array_index >= EVENT_BATCH) {\
                output_queue(#which_queue#);\
                #which_array_index#.update(&fi, (u32*)&zero);\
            }\
            else #which_array_index#.update(&fi, array_index);\
            #which_used#.update(&fi, (u8*)&zero);'

    def update_event_count_part(self) :
        return r'\
            #need_update#\
            #poll_count#.update(&pid, e_count);'
    ###############################################################
    # here we start to attach function
    ###############################################################
    def attach_function(self) :
        prog = ""
        for func_name in self.ovs_func_name:
            func = 'int ' + self.function_start(func_name)
            func += self.set_val_part()
            func += self.parse_packet_new_part()
            func = self.replace_sentence(func, "#what_code_insert#", self.extract_from_packet_part())
            func += self.parse_packet_new_part()
            func = self.replace_sentence(func, "#what_code_insert#", self.occur_event_part())
            func += self.update_event_count_part()
            func += self.function_end()

            func = self.replace_sentence(func, "#which_used#", func_name[:13] + "_used")
            func = self.replace_sentence(func, "#which_array#", func_name[:13] + "_array")
            func = self.replace_sentence(func, "#which_array_index#", func_name[:13] + "_index")
            func = self.replace_sentence(func, "#which_pkt_len#", func_name[:13] + "_pkt_len")
            func = self.replace_sentence(func, "#which_queue#", self.which_queue_use(func_name[:13]))
            func = self.replace_sentence(func, "#param_position#", self.param_pos(func_name[:13]))
            func = self.replace_sentence(func, "#what_evt_type#", self.which_queue_use(func_name[:13]))

            if func_name.find("virtio_dev_tx") != -1 or func_name.find("mlx5_tx") != -1 :
                func = self.replace_sentence(func, "#poll_count#", "tx_poll_count")
                if func_name.find("mlx5_tx") != -1 : func = self.replace_sentence(func, "#need_update#", "*e_count += 1;")
                else : func = self.replace_sentence(func, "#need_update#", "")
            else :
                func = self.replace_sentence(func, "#poll_count#", "rx_poll_count")
                if func_name.find("virtio_rx") != -1 : func = self.replace_sentence(func, "#need_update#", "*e_count += 1;")
                else : func = self.replace_sentence(func, "#need_update#", "")
            func = self.replace_sentence(func, "#what_function#", func_name)
            prog += func
        return prog
    
    def make_complete_code(self) : 
        prog = self.set_header()
        prog += self.set_event_data_type()
        prog += self.set_event()
        prog += self.set_map()
        prog += self.common_using_func_ringbuf()
        prog += self.attach_function()
        return self.erase_slacks(prog)



        


    

    



