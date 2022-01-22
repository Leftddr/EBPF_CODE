from collections import defaultdict
from queue import PriorityQueue
##############################################################
# We need to hash function to find key in O(1)
##############################################################
class HashTable:
    def __init__(self):
        self.bit_num = 3
        self.zero_multi_num = 7
        self.one_multi_num = 11
        self.divide_num = 100000007
        self.ovs_data = defaultdict()
        self.time_data = defaultdict()

    def hash_function(self, src_addr, dst_addr, src_port, dst_port) :
        source = str(bin(src_addr))[2:] + str(bin(dst_addr))[2:] + str(bin(src_port))[2:] + str(bin(dst_port))[2:]
        '''
        key = 1
        for i in source :
            if i == '1' : key = (key * self.zero_multi_num * self.bit_num) % self.divide_num
            else : key = (key * self.one_multi_num) % self.divide_num
            self.bit_num = (self.bit_num * self.bit_num) % self.divide_num
        
        return (key % self.divide_num)
        '''
        return source
    # 파이썬 우선순위 큐 사용
    # In here, we sort the priority_queue by key (sent_bytes) to calculate comfortably
    def set_value(self, ebpfdata) :
        if ebpfdata == None : return
        key = self.hash_function(ebpfdata.src_addr, ebpfdata.dst_addr, ebpfdata.src_port, ebpfdata.dst_port)
        if self.ovs_data.get(key) == None : self.ovs_data[key] = defaultdict()
        if self.ovs_data[key].get(ebpfdata.tx_or_rx) == None : self.ovs_data[key][ebpfdata.tx_or_rx] = defaultdict()
        if self.ovs_data[key][ebpfdata.tx_or_rx].get(ebpfdata.kvm_or_ovs) == None : self.ovs_data[key][ebpfdata.tx_or_rx][ebpfdata.kvm_or_ovs] = PriorityQueue()
        
        self.ovs_data[key][ebpfdata.tx_or_rx][ebpfdata.kvm_or_ovs].put(ebpfdata)




