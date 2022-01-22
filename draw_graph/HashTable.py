from collections import defaultdict
from queue import PriorityQueue
import random
##############################################################
# We need to hash function to find key in O(1)
##############################################################
class HashTable:
    def __init__(self):
        self.zero_multi_num = 7
        self.one_multi_num = 11
        self.divide_num = 100000007
        self.kvm_data = defaultdict()
        self.ovs_data = defaultdict()
        '''
        self.ts_data = []
        self.cur_ts = 0.00007
        for i in range(1000):
            self.ts_data.append(self.cur_ts)
            self.cur_ts += 0.00001
        '''

    def hash_function(self, src_addr, dst_addr, src_port, dst_port) :
        source = str(bin(src_addr)) + str(bin(dst_addr)) + str(bin(src_port)) + str(bin(dst_port))
        '''
        key = 1
        for i in source :
            if i == '1' : key = (key * self.zero_multi_num) % self.divide_num
            else : key = (key * self.one_multi_num) % self.divide_num
        return (key % self.divide_num)
        '''
        return source
    
    def set_value(self, ebpfdata, kvm_or_ovs) :
        key = self.hash_function(ebpfdata.src_addr, ebpfdata.dst_addr, ebpfdata.src_port, ebpfdata.dst_port)
        
        if kvm_or_ovs == 0 :
            if self.kvm_data.get(key) == None : self.kvm_data[key] = defaultdict()
            if self.kvm_data[key].get(0) == None : self.kvm_data[key][0] = ebpfdata
            if self.kvm_data[key].get(1) == None : self.kvm_data[key][1] = []
            if self.kvm_data[key].get(2) == None : self.kvm_data[key][2] = []

            self.kvm_data[key][1].append(ebpfdata.sent_bytes)
            self.kvm_data[key][2].append(ebpfdata.ts)

        else :
            if self.ovs_data.get(key) == None : self.ovs_data[key] = defaultdict()
            if self.ovs_data[key].get(0) == None : self.ovs_data[key][0] = ebpfdata
            if self.ovs_data[key].get(1) == None : self.ovs_data[key][1] = []
            if self.ovs_data[key].get(2) == None : self.ovs_data[key][2] = []

            #idx = random.randint(0, len(self.ts_data) - 1)
            
            self.ovs_data[key][1].append(ebpfdata.sent_bytes)
            
            #self.ovs_data[key][2].append(self.ts_data[idx])
            self.ovs_data[key][2].append(ebpfdata.ts)




