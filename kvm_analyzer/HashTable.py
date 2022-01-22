from collections import defaultdict
from queue import PriorityQueue
##############################################################
# We need to hash function to find key in O(1)
##############################################################
class HashTable:
    def __init__(self, file_list):
        self.file_list = file_list
        self.zero_multi_num = 7
        self.one_multi_num = 11
        self.divide_num = 1000000007
        self.kvm_data = defaultdict()
        
    def hash_function(self, src_addr, dst_addr, src_port, dst_port) :
        source = str(bin(src_addr))[2:] + str(bin(dst_addr))[2:] + str(bin(src_port))[2:] + str(bin(dst_port))[2:]
        '''
        key = 1
        for i in source :
            if i == '1' : key = (key * self.zero_multi_num) % self.divide_num
            else : key = (key * self.one_multi_num) % self.divide_num
        return (key % self.divide_num)
        '''
        return source
    
    #우선순위 큐를 사용할때는 sequence num이 작은 것부터 사용한다.
    def set_value(self, key, ebpfdata) :
        trans_or_recv = 0 if ebpfdata.evt_type == 2 else 1
        if self.kvm_data.get(key) == None : self.kvm_data[key] = defaultdict()
        if self.kvm_data[key].get(trans_or_recv) == None : self.kvm_data[key][trans_or_recv] = PriorityQueue()

        #self.kvm_data[key][trans_or_recv].put(((ebpfdata.seq_num, ebpfdata.sent_bytes), ebpfdata))
        self.kvm_data[key][trans_or_recv].put(ebpfdata)




