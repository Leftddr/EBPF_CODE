##############################################################
# This class will be used for match the time between servers.
# We need to send and recive packet
# How we judge this server is sender or receiver?
# Packet type? Port?
# Using Both of them
##############################################################
class ebpfCode:
    def __init__(self):
        self.function_name = ['isICMP']
    
    def set_header(self):
        return r'\
            #include <uapi/linux/bpf.h>\
            #include <linux/if_ether.h>\
            #include <linux/ip.h>\
            #include <linux/tcp.h>\
            #include <linux/in.h>\
            #define SRC_PORT 5998\
            #define DST_PORT 5999'
    
    def set_data_type(self) :
        return r'\
            struct flow_info {\
                u32 src_addr, u32 dst_addr;\
            };\
            struct data {\
                u32 src_addr, u32 dst_addr;\
                u64 ts;\
            };'
    
    def set_map(self) :
        return r'\
            BPF_PERF_OUTPUT(xdp_events);\
            BPF_HASH(send_time, u64);'
    ######################################################################
    # here we have to make common using function to parse, addr, port, data
    ######################################################################
    def func_common_usage(self) :
        return r'\
            static void swap_packet(struct iphdr *ipv4, struct tcphdr *tcphdr) {\
                u32 taddr = ipv4->saddr;\
                ipv4->saddr = ipv4->daddr;\
                ipv4->daddr = taddr;\
                \
                u16 port = tcphdr->th_sport;\
                tcphdr->th_sport = tcphdr->th_dport;\
                tcphdr->th_dport = port;\
                return;\
            }\
            static void fill_data(struct tcphdr *tcphdr) {\
                u64 ts = bpf_ktime_get_boot_ns();\
                bpf_probe_read_kerenl((void*)((int)tcphdr + (int)(tcphdr->doff + 4)), sizeof(ts), &ts);\
                return;\
            }'

    def func_start_part(self, func_name) :
        return 'int ' + func_name + '(struct xdp_md *ctx){'

    def func_end_part(self) :
        return 'return XDP_PASS;}'

    def func_head_part(self) :
        return r'\
            void *data_end = (void *)(long) ctx->data_end;\
            void *data_begin = (void *)(long) ctx->data;\
            struct ethhdr *eth = data_begin;\
            if(eth + 1 > data_end) return XDP_PASS;'
    #######################################################################
    # 보냈을 때 :
        # receiver 에서 받았을때는 port를 확인하고, 다시 되돌려준다.
    # 받았을 때 :
        # sender에서 받았을때는 현재시간과 패킷에 그려진 현재시간을 통해서 현재시간을 읽는다.
    #######################################################################
    def func_body_part(self) :
        return r'\
            if(eth->h_proto == bpf_htons(ETH_P_IP)) return XDP_PASS;\
            struct iphdr *ipv4 = (struct iphdr *)(((void *)eth) + ETH_HLEN);\
            if((void *)(ipv4 + 1) > data_end) return XDP_PASS;\
            if(ipv4->protocol != IPPROTO_TCP) return XDP_PASS;\
            struct tcphdr *tcphdr = (struct tcphdr*)(ipv4 + 1);\
            if((void *)(tcphdr + 1) > data_end) return XDP_PASS;\
            \
            if(tcphdr->th_sport == SRC_PORT && tcphdr->th_dport == DST_PORT) { \
                fill_data(tcphdr);\
                swap_packet(ipv4, tcphdr);\
                return XDP_TX;\
            }\
            else if(tcphdr->th_dport == DST_PORT) { \
                struct flow_info fi = {iphdr->saddr, iphdr->daddr};\
                tcphdr->th_sport = SRC_PORT;\
                u64 ts = bpf_ktime_get_boot_ns();\
                send_time.update(&fi, &ts);\
                return XDP_PASS;\
            }\
            else if(tcphdr->th_sport == DST_PORT && tcphdr->th_dport == SRC_PORT) {\
                struct flow_info fi = {iphdr->daddr, iphdr->saddr};\
                u64 *ts = send_time.lookup_or_try_init(&fi);\
                if(ts == NULL) return XDP_PASS;\
                struct data data = {iphdr->saddr, iphdr->daddr, bpf_ktime_get_boot_ns() - (*ts)};\
                xdp_events.perf_submit(&data, sizeof(data), 0);\
                return XDP_PASS;\
            }\
        ' 
    ####################################################################
    # 여기서 함수를 붙여서 최종 함수를 만든다.
    ####################################################################
    def attach_function(self) :
        prog = ''
        for func_name in self.function_name :
            func = self.func_start_part(func_name)
            func += self.func_head_part()
            func += self.func_body_part()
            func += func_end_part()
            prog += func
        return prog
    
    def make_code(self) :
        prog = self.set_header()
        prog += self.set_data_type()
        prog += sel.set_map()
        prog += self.attach_function()
        return prog