from bcc import BPF
import os
import time
import multiprocessing
import logging
from collections import defaultdict
import ebpf_event_type as dtype
import threading as th

class ebpfPythonCode :
    def __init__(self, prog, func_list, ovs_file_name, kvm_file_name) :
        self.b = BPF(text = prog, cflags = ["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
        self.kernel_func_list = func_list

        self.b['events'].open_ring_buffer(self.event_callback)
        
        self.ovs_file_name = ovs_file_name
        self.kvm_file_name = kvm_file_name
        self.EVENT_BATCH = 5
        self.ovs_fp = None
        self.kvm_fp = None

        self.my_address = '10.2.1.1'
        self.send_data_cnt = 0
        self.threshold = 100
        self.calculate_server_path = 'sonic@10.20.16.135:/home/sonic/kvm_analyzer/kvm_data/'
        self.kvm_time_exec_name = './kvm_time'
        self.kvm_time_file_name = './kvm_time.txt'

        self.seq_max = 2147483647
        self.attach_function()

    def attach_function(self):
        for func_name in self.kernel_func_list:
            if func_name.find("sock") != -1:
                self.b.attach_kprobe(event = func_name, fn_name = "kprobe__" + func_name)
                self.b.attach_kretprobe(event = func_name, fn_name = "kretprobe__" + func_name) 
            else :
                self.b.attach_kprobe(event = func_name, fn_name = "kprobe__" + func_name)

    #####################################################
    # This code first send time to calculate server.
    #####################################################
    def send_data_time(self):
        multi_num = 1000000000
        try :
            os.system('rm -rf ' + self.kvm_time_file_name)
            os.system(self.kvm_time_exec_name)
        except :
            logging.exception("message")
            return False

        fp = open(self.kvm_time_file_name, 'r')
        cur_time_line = fp.readline().split(' ')
        mono_time_line = fp.readline().split(' ')

        cur_time = int(cur_time_line[0]) * multi_num + int(cur_time_line[1])
        mono_time = int(mono_time_line[0]) * multi_num + int(mono_time_line[1])

        file_name = self.my_address + '_time'
        fp = open(file_name, 'w')
        fp.write(str(cur_time) + ' ' + str(mono_time))
        fp.close()

        try :
            os.system('sshpass -p "skwx4216@!" scp -P 51111 ' + file_name + ' ' + self.calculate_server_path + self.my_address + '_time')
        except :
            return False
        return True
    
    #####################################################
    # send data file to calculate server
    # First, cp the file to tmp file
    # Second, send the file
    # third, remove the tmp file
    #####################################################
    def send_data_file(self) :
        if os.path.isfile(self.ovs_file_name) == True:
            ovs_file_name_tmp = self.ovs_file_name + '_tmp'
            os.system('cp ' + self.ovs_file_name + ' ' + ovs_file_name_tmp)
            command = 'sshpass -p "skwx4216@!" scp -P 51111 ' + ovs_file_name_tmp + ' ' + self.calculate_server_path + self.my_address + '_ovs'
            os.system(command)
            os.system('rm -rf ' + ovs_file_name_tmp)
        if os.path.isfile(self.kvm_file_name) == True:
            kvm_file_name_tmp = self.kvm_file_name + '_tmp'
            os.system('cp ' + self.kvm_file_name + ' ' + kvm_file_name_tmp)
            command = 'sshpass -p "skwx4216@!" scp -P 51111 ' + kvm_file_name_tmp + ' ' + self.calculate_server_path + self.my_address + '_kvm'
            os.system(command)
            os.system('rm -rf ' + kvm_file_name_tmp)

    #####################################################
    # we make ringbuf callback function
    #####################################################
    def write_log(self, ebpfDataBatch):
        if ebpfDataBatch == None : return
        
        self.ovs_fp = open(self.ovs_file_name, 'a')
        self.kvm_fp = open(self.kvm_file_name, 'a')
        for ebpf_data in ebpfDataBatch.arr.arr :
            if ebpf_data == None : continue
            if ebpf_data.sent_bytes == 0 : continue
            if ebpf_data.src_addr == 0 or ebpf_data.dst_addr == 0 or ebpf_data.src_port == 0 or ebpf_data.dst_port == 0 : continue
            elif ebpf_data.src_port == 51111 or ebpf_data.dst_port == 51111 : continue
            content = str(ebpf_data.evt_type) + ' ' + str(ebpf_data.e_count) + ' '
            content += str(ebpf_data.src_addr) + ' ' + str(ebpf_data.dst_addr) + ' '
            content += str(ebpf_data.src_port) + ' ' + str(ebpf_data.dst_port) + ' '
            content += str(ebpf_data.ts) + ' '
            content += str(ebpf_data.sent_bytes) + ' ' + str(ebpf_data.seq_num) + '\n'
            if ebpf_data.seq_num == 0 : self.ovs_fp.write(content)
            else : self.kvm_fp.write(content)
        self.ovs_fp.close()
        self.kvm_fp.close()

        self.send_data_cnt += 1
        if self.send_data_cnt >= self.threshold :
           send_thread = th.Thread(target = self.send_data_file)
           send_thread.start()
           send_thread.join()
           self.send_data_cnt = 0

    def event_callback(self, ctx, data, size) :
        ebpfDataBatch = self.b['events'].event(data)
        self.write_log(ebpfDataBatch)

    #####################################################
    # We use ringbuf event.
    #####################################################

    def start_function(self):
        if self.send_data_time() == False :
            print('cannot send time data to calculate server')
            return

        while True:
            try :
                #self.b.trace_print()
                self.b.ring_buffer_consume()
            except :
                logging.exception('message')
                return

