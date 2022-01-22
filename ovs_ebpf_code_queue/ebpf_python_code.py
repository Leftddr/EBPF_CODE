from bcc import BPF
import os
import time
import multiprocessing
import ebpf_data_class as ebpfda
from collections import defaultdict
import logging
import threading as th
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

        self.b['virtio_dev_tx_ringbuf'].open_ring_buffer(self.virtio_dev_tx_callback)
        self.b['mlx5_tx_burst_ringbuf'].open_ring_buffer(self.mlx5_tx_burst_callback)
        self.b['virtio_dev_rx_ringbuf'].open_ring_buffer(self.virtio_dev_rx_callback)
        self.b['mlx5_rx_burst_ringbuf'].open_ring_buffer(self.mlx5_rx_burst_callback)

        self.ovs_function = ["virtio_dev_tx_split", "virtio_dev_tx_packed", "mlx5_tx_burst_none_empw" ,\
            "virtio_dev_rx_split", "virtio_dev_rx_packed", "mlx5_rx_burst_vec"]
        #self.ovs_function = ["mlx5_rx_burst_vec", "virtio_dev_rx_split"]
        self.origin_function = ["virtio_dev_tx", "virtio_dev_tx", "mlx5_tx_burst", "virtio_dev_rx", "virtio_dev_rx", "mlx5_rx_burst"]

        self.library_name = defaultdict()
        self.library_path = defaultdict()

        self.my_address = '10.2.1.1'
        self.ovs_file_name_tx = self.my_address + "_ovs_tx"
        self.ovs_file_name_rx = self.my_address + "_ovs_rx"

        self.calculate_server = 'sonic@10.20.16.135:/home/sonic/ovs_analyzer/ovs_data/'
        self.send_cnt = 0
        self.threshold = 100
        self.thread_running = False
        self.ovs_time_exec_name = './ovs_time'
        self.ovs_time_file_name = './ovs_time.txt'

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
    
    ###############################################################
    # little endian and big endian
    ###############################################################
    def change_endian(self, number):
        number = str(bin(number))[2:]
        number = number[::-1]
        while len(number) % 8 != 0 : number += '0'

        change_endian_num = ''

        next_num_len = len(number)
        prev_num_len = next_num_len - 8

        while prev_num_len >= 0:
            change_endian_num += number[prev_num_len : next_num_len]
            prev_num_len -= 8; next_num_len -= 8

        retval = 0
        multi_num = 1;

        for bit in change_endian_num :
            if bit == '1' : retval += multi_num
            multi_num *= 2

        return retval
    ###############################################################
    # we need to send time data to match time between virtual machine and host
    ###############################################################
    def send_data_time(self) :
        multi_num = 1000000000
        try : 
            os.system('rm -rf ' + self.ovs_time_file_name)
            os.system(self.ovs_time_exec_name)
        except : 
            logging.exception("message")
            return False

        fp = open(self.ovs_time_file_name, 'r')
        cur_time_line = fp.readline().split(' ')
        mono_time_line = fp.readline().split(' ')

        cur_time = int(cur_time_line[0]) * multi_num + int(cur_time_line[1][:-1])
        mono_time = int(mono_time_line[0]) * multi_num + int(mono_time_line[1])
        
        file_name = self.my_address + '_time'
        fp = open(file_name, 'w')
        fp.write(str(cur_time) + ' ' + str(mono_time))
        fp.close()

        if os.path.isfile(file_name) == True:
            try : 
                os.system('sshpass -p "skwx4216@!" scp -P 51111 ' + file_name + ' ' + self.calculate_server + self.my_address + '_time')
            except : 
                logging.exception("message")
                return False
            return True
        else : return False

    ###############################################################
    # send data to calculate server periodically
    ###############################################################
    def send_data(self):
        if self.thread_running : return
        self.thread_running = True
        if os.path.isfile(self.ovs_file_name_tx) :
            ovs_file_name_tx_tmp = self.ovs_file_name_tx + '_tmp'
            os.system('cp ' + self.ovs_file_name_tx + ' ' + ovs_file_name_tx_tmp)
            os.system('sshpass -p "skwx4216@!" scp -P 51111 ' + self.ovs_file_name_tx + ' ' + self.calculate_server + self.ovs_file_name_tx)
            os.system('rm -rf ' + ovs_file_name_tx_tmp)
        if os.path.isfile(self.ovs_file_name_rx) :
            ovs_file_name_rx_tmp = self.ovs_file_name_rx + '_tmp'
            os.system('cp ' + self.ovs_file_name_rx + ' ' + ovs_file_name_rx_tmp)
            os.system('sshpass -p "skwx4216@!" scp -P 51111 ' + self.ovs_file_name_rx + ' ' + self.calculate_server + self.ovs_file_name_rx)
            os.system('rm -rf ' + ovs_file_name_rx_tmp)
        self.thread_running = False
    
    ################################################################
    # attach function to user space function
    ################################################################
    def attach_function(self) :
        for func_name in self.ovs_function :
            print(func_name)
            if func_name.find("virtio_dev_tx") != -1 or func_name.find("mlx5_rx_burst") != -1:
                self.b.attach_uretprobe(name = self.library_path[func_name] + self.library_name[func_name], sym = func_name, fn_name = func_name)
            else :
                self.b.attach_uprobe(name = self.library_path[func_name] + self.library_name[func_name], sym = func_name, fn_name = func_name)
    
    #################################################################
    # transmit thread
    #################################################################
    def trans_write(self, fp, ebpfDataBatch) :
        if ebpfDataBatch == None : return
        for ebpf_data in ebpfDataBatch.arr.arr :
            if ebpf_data == None : continue
            content = ''
            content += str(self.change_endian(ebpf_data.src_addr)) + ' ' + str(self.change_endian(ebpf_data.dst_addr)) + ' '
            content += str(self.change_endian(ebpf_data.src_port)) + ' ' + str(self.change_endian(ebpf_data.dst_port)) + ' '
            content += str(ebpf_data.ts) + ' ' + str(ebpf_data.pkt_len) + ' '
            content += str(self.change_endian(ebpf_data.sent_seq)) + ' ' + str(self.change_endian(ebpf_data.recv_ack)) + '\n'
            fp.write(content)
        
    def virtio_dev_tx_callback(self, ctx, data, size) :
        fp = open(self.ovs_file_name_tx, 'a')
        ebpfDataBatch = self.b['virtio_dev_tx_ringbuf'].event(data)
        self.trans_write(fp, ebpfDataBatch)
        fp.close()

        if self.thread_running == False : self.send_cnt += 1
        if self.send_cnt >= self.threshold :
            self.send_cnt = 0
            send_thread = th.Thread(target = self.send_data)
            send_thread.start()
            send_thread.join()

    def mlx5_tx_burst_callback(self, ctx, data, size) :
        fp = open(self.ovs_file_name_tx, 'a')
        ebpfDataBatch = self.b['mlx5_tx_burst_ringbuf'].event(data)
        self.trans_write(fp, ebpfDataBatch)
        fp.close()
    
        if self.thread_running == False : self.send_cnt += 1
        if self.send_cnt >= self.threshold :
            self.send_cnt = 0
            send_thread = th.Thread(target = self.send_data)
            send_thread.start()
            send_thread.join()
    
    ###################################################################
    # receive thread
    ###################################################################
    def recv_write(self, fp, ebpfDataBatch) :
        if ebpfDataBatch == None : return
        for ebpf_data in ebpfDataBatch.arr.arr :
            if ebpf_data == None : continue
            content = ''
            content += str(self.change_endian(ebpf_data.src_addr)) + ' ' + str(self.change_endian(ebpf_data.dst_addr)) + ' '
            content += str(self.change_endian(ebpf_data.src_port)) + ' ' + str(self.change_endian(ebpf_data.dst_port)) + ' '
            content += str(ebpf_data.ts) + ' ' + str(ebpf_data.pkt_len) + ' '
            content += str(self.change_endian(ebpf_data.sent_seq)) + ' ' + str(self.change_endian(ebpf_data.recv_ack)) + '\n'
            fp.write(content)

    def virtio_dev_rx_callback(self, ctx, data, size) :
        fp = open(self.ovs_file_name_rx, 'a')
        ebpfDataBatch = self.b['virito_dev_rx_ringbuf'].event(data)
        self.recv_write(fp, ebpfDataBatch)    
        fp.close()

        if self.thread_running == False : self.send_cnt += 1
        if self.send_cnt >= self.threshold :
            self.send_cnt = 0
            send_thread = th.Thread(target = self.send_data)
            send_thread.start()
            send_thread.join()

    def mlx5_rx_burst_callback(self, ctx, data, size):
        fp = open(self.ovs_file_name_rx, 'a')
        ebpfDataBatch = self.b['mlx5_rx_burst_ringbuf'].event(data)
        self.recv_write(fp, ebpfDataBatch)
        fp.close()

        if self.thread_running == False : self.send_cnt += 1
        if self.send_cnt >= self.threshold :
            self.send_cnt = 0
            send_thread = th.Thread(target = self.send_data)
            send_thread.start()
            send_thread.join()
    
    ####################################################################
    # We use ringbuf event so we must polling event continuely
    ####################################################################

    def start_function(self) :
        if self.send_data_time() == False : 
            print('Please send time data to calculate server')
            return 

        while True:
            try :
                #self.b.trace_print()
                self.b.ring_buffer_consume()
            except :
                logging.exception('message')
                return
