##############################################################
# src_addr -> dst_addr
# src_port -> dst_port
# ts, sent_bytes
##############################################################
class ebpfData:
    def __init__(self, kvm_ebpfdata, ovs_ebpfdata, tx_or_rx, kvm_or_ovs) :
        self.src_addr = None
        self.dst_addr = None
        self.src_port = None
        self.dst_port = None
        self.ts = None
        self.sent_bytes = None
        self.seq_num = None
        self.tx_or_rx = tx_or_rx
        self.kvm_or_ovs = kvm_or_ovs

        if kvm_ebpfdata == None :
            self.src_addr = int(ovs_ebpfdata[0])
            self.dst_addr = int(ovs_ebpfdata[1])
            self.src_port = int(ovs_ebpfdata[2])
            self.dst_port = int(ovs_ebpfdata[3])
            self.ts = int(ovs_ebpfdata[4])
            self.sent_bytes = int(ovs_ebpfdata[5])
            self.seq_num = int(ovs_ebpfdata[6])
        else :
            self.src_addr = int(kvm_ebpfdata[2])
            self.dst_addr = int(kvm_ebpfdata[3])
            self.src_port = int(kvm_ebpfdata[4])
            self.dst_port = int(kvm_ebpfdata[5])
            self.ts = int(kvm_ebpfdata[6])
            self.sent_bytes = int(kvm_ebpfdata[7])
            self.seq_num = int(kvm_ebpfdata[8])
        
    def __lt__(self, other) :
        if self.seq_num == other.seq_num :
            return self.sent_bytes < other.sent_bytes
        else : return self.seq_num < other.seq_num
            
