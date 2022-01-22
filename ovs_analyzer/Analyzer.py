import os
import time
from collections import defaultdict
import threading as th
import ebpf_data_class as dtype
import HashTable as ht
##############################################################
# Local Analyzer read file and set value to hashtable
# There cannot not be same src_addr
# We need hash table pre local server because matching between kvm and ovs
# We need to make bring file to here, you need to first set ssh-key-id to get data without password
# We need to match sequence num to match server, port, file etc
##############################################################
class Analyzer:
    def __init__(self):
        self.server_list = ['10.2.1.1', '10.2.1.2']
        self.kvm_folder = '../kvm_analyzer/kvm_data/'
        self.ovs_folder = './ovs_data/'
        self.per_file_seek = defaultdict()
        self.HashTable = ht.HashTable()
        self.file_list = []
        self.time_file_list = []
        self.time_server = []

        self.kvm_data_len = 9
        self.ovs_data_len = 8

        for server in self.server_list :
            kvm_file = self.kvm_folder + server + '_kvm'
            ovs_file_tx = self.ovs_folder + server + '_ovs_tx'
            ovs_file_rx = self.ovs_folder + server + '_ovs_rx'
            self.per_file_seek[kvm_file] = 0
            self.per_file_seek[ovs_file_tx] = 0
            self.per_file_seek[ovs_file_rx] = 0
            self.file_list.append(kvm_file); self.file_list.append(ovs_file_tx); self.file_list.append(ovs_file_rx)

        for server in self.server_list:
            self.time_file_list.append(self.kvm_folder + server + '_time')
            self.time_file_list.append(self.ovs_folder + server + '_time')
            self.time_server.append(server)
            self.time_server.append(server) 
   
    ###############################################
    # match time between virtual machine and host
    ###############################################
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
     
    def match_time(self):
        for idx, time_file in enumerate(self.time_file_list): 
            key = self.time_server[idx]
            if os.path.isfile(time_file) == False : return False
            fp = open(time_file, 'r')
            data = fp.readline().split(' ')
            fp.close()
            
            if self.HashTable.time_data.get(key) == None : self.HashTable.time_data[key] = defaultdict()
            if time_file.find("kvm") != -1 : self.HashTable.time_data[key][1] = data
            else : self.HashTable.time_data[key][0] = data

    def calculate_diff_time(self, data1, data2):
        diff_boot_time = abs(int(data1[1]) - int(data2[1]))
        diff_cur_time = abs(int(data1[0]) - int(data2[0]))

        return abs(diff_boot_time - diff_cur_time)

    ###############################################
    # we need read thread
    ###############################################
    def read_thread(self) :
        threshold = 100
        while True:
            for file in self.file_list :
                if os.path.isfile(file) == False : continue
                
                fp = open(file, 'r')
                fp.seek(self.per_file_seek[file], 0)
                
                cur_cnt = 0
                line = fp.readline()

                while line is not None :
                    self.per_file_seek[file] = fp.tell()
                    data = line.split(' ')

                    if file.find("kvm") != -1 :
                        if len(data) != self.kvm_data_len : 
                            ebpfdata = None
                            self.HashTable.set_value(ebpfdata)
                        else : 
                            ebpfdata = dtype.ebpfData(data, None, 0 if int(data[0]) == 2 else 1, 1)
                            if ebpfdata.sent_bytes > 0 : 
                                self.HashTable.set_value(ebpfdata)
                    else :
                        if len(data) != self.ovs_data_len : 
                            ebpfdata = None 
                            self.HashTable.set_value(ebpfdata)
                        else : 
                            ebpfdata = dtype.ebpfData(None, data, 0 if file.find("tx") != -1 else 1, 0)
                            if ebpfdata.sent_bytes > 0 : 
                                self.HashTable.set_value(ebpfdata)

                    cur_cnt += 1
                    if cur_cnt >= threshold : break
                    line = fp.readline()
                fp.close()
    ##################################################
    # we need calculate thread between kvm and ovs
    #################################################
    def calculate_thread(self) :
        threshold = 100
        ovs_file_name = 'ovs_result'
        while True :
            for key in list(self.HashTable.ovs_data.keys()):
                fp = open(ovs_file_name, 'a')
                for tx_or_rx in range(2) :
                    if self.HashTable.ovs_data[key].get(tx_or_rx) == None : continue
                    if self.HashTable.ovs_data[key][tx_or_rx].get(0) == None or self.HashTable.ovs_data[key][tx_or_rx].get(1) == None : continue
                    if self.HashTable.ovs_data[key][tx_or_rx][0].empty() or self.HashTable.ovs_data[key][tx_or_rx][1].empty() : continue
                    ## 0 => ovs, 1 => kvm
                    kvm_ebpfdata = self.HashTable.ovs_data[key][tx_or_rx][1].get()
                    while self.HashTable.ovs_data[key][tx_or_rx][0].empty() == False :
                        ovs_ebpfdata = self.HashTable.ovs_data[key][tx_or_rx][0].get()
                        
                        time_key = self.change_addr_to_str(ovs_ebpfdata.src_addr)
                        if self.HashTable.time_data.get(time_key) == None : break
                        if self.HashTable.time_data[time_key].get(0) == None or self.HashTable.time_data[time_key].get(1) == None : break
                        #if ovs_ebpfdata.sent_bytes >= kvm_ebpfdata.sent_bytes:
                        if ovs_ebpfdata.seq_num >= kvm_ebpfdata.seq_num :
                            ts = abs(ovs_ebpfdata.ts - kvm_ebpfdata.ts)
                            diff_ts = self.calculate_diff_time(self.HashTable.time_data[time_key][0], self.HashTable.time_data[time_key][1])
                            ts = abs(ts - diff_ts)
                            #print(ovs_ebpfdata.src_addr, ovs_ebpfdata.dst_addr, ovs_ebpfdata.src_port, ovs_ebpfdata.dst_port, ovs_ebpfdata.seq_num, ovs_ebpfdata.ts)
                            #print(kvm_ebpfdata.src_addr, kvm_ebpfdata.dst_addr, kvm_ebpfdata.src_port, kvm_ebpfdata.dst_port, kvm_ebpfdata.seq_num, kvm_ebpfdata.ts)
                            #print(ts)
                            #time.sleep(1)
                            content = str(ovs_ebpfdata.src_addr) + ' ' + str(ovs_ebpfdata.dst_addr) + ' '
                            content += str(ovs_ebpfdata.src_port) + ' ' + str(ovs_ebpfdata.dst_port) + ' '
                            content += str(ts) + ' ' + str(ovs_ebpfdata.sent_bytes) + '\n'
                            fp.write(content)

                            prev_seq_num = kvm_ebpfdata.seq_num
                            while self.HashTable.ovs_data[key][tx_or_rx][1].empty() == False and prev_seq_num == kvm_ebpfdata.seq_num :
                                kvm_ebpfdata = self.HashTable.ovs_data[key][tx_or_rx][1].get()
                            break
                fp.close()
    ########################################################
    # calculate start
    ########################################################

    def start_function(self) :
        self.match_time()
        print('start.....')
        read_thread = th.Thread(target = self.read_thread)
        read_thread.start()

        calculate_thread = th.Thread(target = self.calculate_thread)
        calculate_thread.start()

        read_thread.join()
        calculate_thread.join()
                

        

                    
