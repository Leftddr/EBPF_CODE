class ebpfData:
    def __init__(self, data):
        self.divide_num = 1000000000
        self.src_addr = int(data[0])
        self.dst_addr = int(data[1])
        self.src_port = int(data[2])
        self.dst_port = int(data[3])
        self.ts = float(data[4]) / self.divide_num
        self.sent_bytes = int(data[5])
