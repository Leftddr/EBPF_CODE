from collections import defaultdict

class ebpfCode :
    ############################################################################
    # we only set function name and change function name to event function name.
    # what we need function?
    # virtio_dev_tx_split_exit, virtio_dev_tx_packed_exit, mlx5_tx_burst_none_empw
    # virtio_dev_rx_split_enter, virtio_dev_rx_packed_enter, mlx5_rx_burst_vec_exit
    ############################################################################
    def __init__(self):
        self.ovs_func_name = ["virtio_dev_tx", "virtio_dev_tx", "mlx5_tx_burst", "virtio_dev_rx", "virtio_dev_rx", "mlx5_rx_burst"]

    def set_header(self):
        return r'\
            #include <linux/sched.h>\
            #include <uapi/linux/ptrace.h>\
            #include "include/mbuf.h"\
            #include "include/packet.h"\
            #define PACKET_PARSE 32\
            #define EVENT_BATCH 5'

    def set_event_data_type(self) :
        return r'\
            struct data_type {\
                u32 src_addr, dst_addr;\
                u16 src_port, dst_port;\
                u32 pid;\
                u64 ts;\
                u64 pkt_len;\
                u64 e_count;\
            };\
            struct event_type {\
                struct data_type arr[EVENT_BATCH];\
            };\
            struct flow_info {\
                u32 pid;\
                u32 src_addr, dst_addr;\
            };'
    
    def set_map(self):
        return r'\
            BPF_HASH(tx_poll_count, u64);\
            BPF_HASH(rx_poll_count, u64);\
            BPF_QUEUE(virtio_dev_tx_queue, struct event_type, 10240); \
            BPF_QUEUE(mlx5_tx_burst_queue, struct event_type, 10240); \
            BPF_QUEUE(virtio_dev_rx_queue, struct event_type, 10240); \
            BPF_QUEUE(mlx5_rx_burst_queue, struct event_type, 10240); \
            BPF_ARRAY(virtio_dev_tx_array, struct data_type, 64); \
            BPF_ARRAY(mlx5_tx_burst_array, struct data_type, 64); \
            BPF_ARRAY(virtio_dev_rx_array, struct data_type, 64); \
            BPF_ARRAY(mlx5_rx_burst_array, struct data_type, 64); \
            BPF_HASH(virtio_dev_tx_index, struct flow_info); \
            BPF_HASH(mlx5_tx_burst_index, struct flow_info); \
            BPF_HASH(virtio_dev_rx_index, struct flow_info); \
            BPF_HASH(mlx5_rx_burst_index, struct flow_info); \
            BPF_HASH(virtio_dev_tx_pkt_len, struct flow_info); \
            BPF_HASH(mlx5_tx_burst_pkt_len, struct flow_info); \
            BPF_HASH(virtio_dev_rx_pkt_len, struct flow_info); \
            BPF_HASH(mlx5_rx_burst_pkt_len, struct flow_info); \
            BPF_HASH(virtio_dev_tx_used, struct flow_info); \
            BPF_HASH(mlx5_tx_burst_used, struct flow_info); \
            BPF_HASH(virtio_dev_rx_used, struct flow_info); \
            BPF_HASH(mlx5_rx_burst_used, struct flow_info);'
        
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
        if func_name.find("mlx5") != -1 : return "PT_REGS_PARAM2"
        else : return "PT_REGS_PARM4"

    def common_using_func(self) :
        return r'\
            static inline void output_queue(int which_queue) {\
                struct event_type event;\
                for(u32 i = 0 ; i < EVENT_BATCH ; i++) {\
                    struct data_type *data;\
                    if(which_queue == 0) data = virtio_dev_tx_array.lookup(&i);\
                    else if(which_queue == 1) data = mlx5_tx_burst_array.lookup(&i);\
                    else if(which_queue == 2) data = virtio_dev_rx_array.lookup(&i);\
                    else data = mlx5_rx_burst_array.lookup(&i);\
                    if(data == NULL) continue;\
                    bpf_probe_from_kernel(&(event.arr[i]), sizeof(struct data_type), data);\
                }\
                if(which_queue == 0) virtio_dev_tx_queue.push(&event, BPF_EXIST);\
                else if(which_queue == 1) mlx5_tx_burst_queue.push(&event, BPF_EXIST);\
                else if(which_queue == 2) virtio_dev_rx_queue.push(&event, BPF_EXIST);\
                else mlx5_rx_burst_queue.push(&event, BPF_EXIST);\
            }'
    #######################################################################
    # packet parsing function part
    #######################################################################
    def set_val_part(self) :
        return r'\
            u32 pid = bpf_get_current_pid_tgid(), zero = 0, one = 1;\
            u64 *e_count = #poll_count#.lookup_or_try_init(&pid, &zero);\
            if(e_count == NULL) return 0;\
            struct rte_mbuf **pkts = (struct rte_mbuf**)#param_position#(ctx);\
            s32 pkt_cnt = PT_REGS_RC(ctx);'
    
    def extract_from_packet_part(self):
        return r'\
            u64 *pkt_len = #which_pkt_len#.lookup_or_try_init(&fi, &zero);\
            if(pkt_len == NULL) continue;\
            u8 *used = #which_used#.lookup_or_try_init(&fi, &zero);\
            if(used == NULL) continue; \
            *pkt_len += mbuf->pkt_len;\
            #which_pkt_len#.update(&fi, pkt_len);\
            #which_used#.update(&fi, &one);'
    
    def parse_packet_part(self) :
        return r'\
            for(int i = 0 ; i < PACKET_PARSE ; i++) {\
                if(i >= pkt_cnt) break;\
                struct rte_mbuf *pkt = pkts[i];\
                if(pkt == NULL) break;\
                struct rte_ipv4_hdr ip_hdr;\
                char *ip_hdr_addr = mbuf->buf_addr + mbuf->data_off + sizeof(struct rte_ether_hdr);\
                if(bpf_probe_read(&ip_hdr, (size_t)sizeof(ip_hdr), ip_hdr_addr)) break;\
                struct flow_info fi = {pid, ip_hdr.src_addr, ip_hdr.dst_addr};\
                #what_code_insert#\
            }'
    
    def occur_event_part(self) :
        return r'\
            u8 *used = #which_used#.lookup(&fi);\
            if(used == NULL || *used == 0) continue; \
            u64 *pkt_len = #which_pkt_len#.lookup(&fi); \
            if(pkt_len == NULL) continue;\
            u32 *array_index = #which_array_index#.lookup_or_try_init(&fi, &zero);\
            if(array_index == NULL) continue; \
            struct data_type data = {fi.src_addr, fi.dst_addr, 0, 0, pid, bpf_ktime_get_ns(), *pkt_len, *e_count};\
            #which_array#.update(array_index, &data);\
            \
            (*array_index)++;\
            if(*array_index >= EVENT_BATCH) {\
                output_queue(#which_queue#);\
                #which_array_index#.update(&fi, &zero);\
            }\
            #which_used#.update(&fi, &zero);'
    ###############################################################
    # here we start to attach function
    ###############################################################
    def attach_function(self) :
        prog = ""
        for func_name in self.ovs_func_name:
            func = 'int ' + self.function_start(func_name)
            func += self.set_val_part()
            func += self.parse_packet_part()
            func = self.replace_sentence(func, "#what_code_insert#", self.extract_from_packet_part())
            func += self.parse_packet_part()
            func = self.replace_sentence(func, "#what_code_insert#", self.occur_event_part())
            func += self.function_end()

            func = self.replace_sentence(func, "#which_used#", func_name + "_used")
            func = self.replace_sentence(func, "#which_array#", func_name + "_array")
            func = self.replace_sentence(func, "#which_array_index#", func_name + "_index")
            func = self.replace_sentence(func, "#which_pkt_len#", func_name + "_pkt_len")
            func = self.replace_sentence(func, "#which_queue#", self.which_queue_use(func_name))
            func = self.replace_sentence(func, "#param_position#", self.param_pos(func_name))

            prog += func

        return prog
    
    def make_complete_code(self) : 
        prog = self.set_header()
        prog += self.set_event_data_type()
        prog += self.set_map()
        prog += self.attach_function()
        return self.erase_slacks(prog)



        


    

    



