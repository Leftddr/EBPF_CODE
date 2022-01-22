import ctypes

class ebpfData:
    def __init__(self, ebpfdata):
        self.src_addr = int(ebpfdata[2])
        self.dst_addr = int(ebpfdata[3])
        self.src_port = int(ebpfdata[4])
        self.dst_port = int(ebpfdata[5])
        self.ts = int(ebpfdata[6])
        self.sent_bytes = int(ebpfdata[7])
        self.seq_num = int(ebpfdata[8])
        self.evt_type = int(ebpfdata[0])
        self.e_count = int(ebpfdata[1])
        
    def __lt__(self, other):
        if self.seq_num == other.seq_num :
            return self.sent_bytes < other.sent_bytes
        else : return self.seq_num < other.seq_num 
