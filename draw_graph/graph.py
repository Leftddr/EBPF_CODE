from collections import defaultdict
import os
import time
import threading as th
import logging
import HashTable as HT
import ebpf_data_class as dtype
import matplotlib.pyplot as plt

class Graph:
    def __init__(self):
        self.kvm_file_name = '../kvm_analyzer/kvm_result'
        self.ovs_file_name = '../ovs_analyzer/ovs_result'
        self.file_list = []
        self.per_file_seek = defaultdict()
        self.HashTable = HT.HashTable()    
        self.data_len = 6
        self.fig = plt.figure()
        self.kvm_data_num = 0
        self.ovs_data_num = 0
        self.total_data_num = 0

        self.set_file_list()
    ###################################
    # common function to use
    ###################################
    def set_file_list(self) :
        self.file_list.append(self.kvm_file_name)
        self.file_list.append(self.ovs_file_name)

        for file_name in self.file_list :
            self.per_file_seek[file_name] = 0

    def change_addr_to_str(self, addr):
        str_addr = str(bin(addr))[2:]
        if len(str_addr) < 32 :
            while len(str_addr) < 32 : str_addr = '0' + str_addr

        str_addr = str_addr[::-1]
        
        dots = []
        num = 1; dot = 0
        for i in range(32):
            if str_addr[i] == '1' : dot += num
            num *= 2
            if num >= 256 :
                dots.append(dot)
                num = 1; dot = 0
        dots.append(dot)

        addr = str(dots[3]) + '.' + str(dots[2]) + '.' + str(dots[1]) + '.' + str(dots[0])
        return addr
    ###################################
    # read thread
    ###################################
    def read_func(self) :
        threshold = 100

        for file_name in self.file_list :
            if os.path.isfile(file_name) == False : continue
            fp = open(file_name, 'r')
            fp.seek(self.per_file_seek[file_name], 0)

            line = fp.readline()
            cur_cnt = 0
                
            while line is not None:
                self.per_file_seek[file_name] = fp.tell()
                if file_name.find("ovs") != -1 : data = line.split(' ')
                else : data = line.split(' ')
                
                if len(data) != self.data_len :
                    line = fp.readline()
                    cur_cnt += 1
                    if cur_cnt >= threshold : break
                    continue

                ebpfdata = dtype.ebpfData(data)
                self.HashTable.set_value(ebpfdata, 0 if file_name.find("kvm") != -1 else 1)
                cur_cnt += 1
                if cur_cnt >= threshold : break
                line = fp.readline()

    ######################################
    # draw thread
    ######################################
    def kvm_draw_func(self) :
        keys = list(self.HashTable.kvm_data.keys())
        data_num = len(keys)
        ax_list = []
        for i in range(self.kvm_data_num) :
            ax_list.append(self.fig.add_subplot(self.total_data_num, 1, i + 1))
        
        for idx, key in enumerate(keys) :
            ax_list[idx].scatter(self.HashTable.kvm_data[key][1], self.HashTable.kvm_data[key][2])
            ax_list[idx].set_title('Virtual Machine to Virtual Machine')
            ax_list[idx].set_xlabel(self.change_addr_to_str(self.HashTable.kvm_data[key][0].src_addr) + ':' + str(self.HashTable.kvm_data[key][0].src_port) + \
                ' to ' + self.change_addr_to_str(self.HashTable.kvm_data[key][0].dst_addr) + ':' + str(self.HashTable.kvm_data[key][0].dst_port) + '\n sent_bytes(bytes)')
            ax_list[idx].set_ylabel('latency (ms)')

    def ovs_draw_func(self) :
        keys = list(self.HashTable.ovs_data.keys())
        data_num = len(keys)
        ax_list = []
        for i in range(self.ovs_data_num) :
            ax_list.append(self.fig.add_subplot(self.total_data_num, 1, i + 1 + self.kvm_data_num))

        for idx, key in enumerate(keys) :
            ax_list[idx].scatter(self.HashTable.ovs_data[key][1], self.HashTable.ovs_data[key][2])
            ax_list[idx].set_title('Virtual Machine to Host Switch')
            ax_list[idx].set_xlabel(self.change_addr_to_str(self.HashTable.ovs_data[key][0].src_addr) + ':' + str(self.HashTable.ovs_data[key][0].src_port) + \
                ' to ' + self.change_addr_to_str(self.HashTable.ovs_data[key][0].dst_addr) + ':' + str(self.HashTable.ovs_data[key][0].dst_port) + '\n sent_bytes(bytes)')
            ax_list[idx].set_ylabel('latency (ms)')
    ##################################
    # start function
    ##################################

    def start_function(self) :
        time_sleep = 2

        while True :
            try :
                self.read_func()
                self.kvm_data_num = len(self.HashTable.kvm_data.keys())
                self.ovs_data_num = len(self.HashTable.ovs_data.keys())
                self.total_data_num = self.kvm_data_num + self.ovs_data_num

                self.kvm_draw_func()
                self.ovs_draw_func()

                plt.subplots_adjust(left = 0.125, bottom = 0.1, right = 0.9, top = 0.9, hspace = 0.5)
                plt.show(block = False)
                plt.pause(time_sleep)
                plt.clf()
                time.sleep(1)
            except :
                logging.exception("message")
                return

        read_thread.join()

