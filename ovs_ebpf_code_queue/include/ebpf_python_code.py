from bcc import BPF
import time
import multiprocessing
import ebpf_data_class
from collections import defaultdict
#################################################################
# This Class include both transmit and receive #
#################################################################
class ebpfPythonCode :
    def __init__(self, prog) :
        self.b = BPF(text = prog, cflags = ["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
        self.virtio_dev_tx_queue = self.b["virtio_dev_tx_queue"]
        self.mlx5_tx_burst_queue = self.b["mlx5_tx_burst_queue"]
        self.virtio_dev_rx_queue = self.b["virtio_dev_rx_queue"]
        self.mlx5_rx_burst_queue = self.b["mlx5_rx_burst_queue"]

        self.ovs_function = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "mlx5_tx_burst_none_empw" ,\
            "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec"]
        self.origin_function = ["virtio_dev_tx", "virtio_dev_tx", "mlx5_tx_burst", "virtio_dev_rx", "virtio_dev_rx", "mlx5_rx_burst"]

        self.library_name = defaultdict()
        self.library_path = defaultdict()

        self.ovs_file_name_tx = "ovs_tx"
        self.ovs_file_name_rx = "ovs_rx"
        self.set_library_path()
        self.attach_function()
    
    def set_library_path(self) :
        self.library_name["virtio_dev_tx_split"] = "librte_vhost.so"
        self.library_name["mlx5_tx_burst_none_empw"] = "librte_net_mlx5.so"
        self.library_name["virtio_dev_tx_packed"] = "librte_vhost.so"
        self.library_name["mlx5_rx_burst_vec"] = "librte_net_mlx5.so"
        self.library_name["virtio_dev_rx_split"] = "librte_vhost.so"
        self.library_name["virtio_dev_rx_packed"] = "librte_vhost.so"

        self.library_path["virtio_dev_tx_split"] = "/usr/local/lib/x86_64-linux-gnu/"
        self.library_path["mlx5_tx_burst_none_empw"] = "/usr/local/lib/x86_64-linux-gnu/"
        self.library_path["virtio_dev_tx_packed"] = "/usr/local/lib/x86_64-linux-gnu/"
        self.library_path["mlx5_rx_burst_vec"] = "/usr/local/lib/x86_64-linux-gnu/"
        self.library_path["virtio_dev_rx_split"] = "/usr/local/lib/x86_64-linux-gnu/"
        self.library_path["virtio_dev_rx_packed"] = "/usr/local/lib/x86_64-linux-gnu/"
    
    ################################################################
    # attach function to user space function
    ################################################################
    def attach_function(self) :
        for idx, func_name in enumerate(self.ovs_function) :
            if func_name.find("virtio_dev_tx") != -1 or func_name.find("mlx5_rx_burst") != -1:
                self.b.attach_uretprobe(name = self.library_path[func_name] + self.library_name[func_name], sym = func_name, fn_name = self.origin_function[idx])
            else :
                self.b.attach_uprobe(name = self.library_path[func_name] + self.library_name[func_name], sym = func_name, fn_name = self.origin_function[idx])
    #################################################################
    # transmit thread
    #################################################################
    def trans_write(self, fp, ebpfDataBatch) :
        if ebpfDataBatch == None : return
        for idx in range(len(ebpfDataBatch.arr)) :
            if ebpfDataBatch.arr[idx] == None : continue
            content = ''
            content += str(ebpfDataBatch.arr[idx].src_addr) + ' ' + str(ebpfDataBatch.arr[idx].dst_addr) + ' '
            content += str(ebpfDataBatch.arr[idx].src_port) + ' ' + str(ebpfDataBatch.arr[idx].dst_port) + ' '
            content += str(ebpfDataBatch.arr[idx].ts) + ' ' + str(ebpfDataBatch.arr[idx].pkt_len) + ' ' + str(ebpfDataBatch.arr[idx].e_count) + '\n'
            fp.write(content)
        
    def transmit_thread(self) :
        while True:
            fp = open(self.ovs_file_name_tx, 'a')
            ebpfDataBatch = self.virtio_dev_tx_queue.pop().value
            trans_write(fp, ebpfDataBatch)

            ebpfDataBatch = self.mlx5_tx_burst_queue.pop().value
            trans_write(fp, ebpfDataBatch)
            fp.close()
    
    ###################################################################
    # receive thread
    ###################################################################
    def recv_write(self, fp, ebpfDataBatch) :
        if ebpfDataBatch == None : return
        for idx in range(len(ebpfDataBatch.arr)) :
            if ebpfDataBatch.arr[idx] == None : continue
            content = ''
            content += str(ebpfDataBatch.arr[idx].src_addr) + ' ' + str(ebpfDataBatch.arr[idx].dst_addr) + ' '
            content += str(ebpfDataBatch.arr[idx].src_port) + ' ' + str(ebpfDataBatch.arr[idx].dst_port) + ' '
            content += str(ebpfDataBatch.arr[idx].ts) + ' ' + str(ebpfDataBatch.arr[idx].pkt_len) + ' ' + str(ebpfDataBatch.arr[idx].e_count) + '\n'
            fp.write(content)

    def receive_thread(self) :
        while True:
            fp = open(self.ovs_file_name_rx, 'a')
            ebpfDataBatch = self.virtio_dev_rx_queue.pop().value
            recv_write(fp, ebpfDataBatch)

            ebpfDataBatch = self.mlx5_rx_burst_queue.pop().value
            recv_write(fp, ebpfDataBatch)
            fp.close()