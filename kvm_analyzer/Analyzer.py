import os
from collections import defaultdict
import time
import HashTable as ht
import ebpf_data_type as dtype
import threading as th
###########################################
# read file seq
# evt_type, e_count, src_addr, dst_addr,
# src_port, dst_port, ts, sent_bytes, seq_num
###########################################
###########################################
# evt_type == 5 : receive side
# evt_type == 2 : send_side
# src_addr, dst_addr, src_port, dst_port ==> hash value
# divide recv side, send side and calculate
###########################################

class Analyzer :
    def __init__(self) :
        self.folder_name = 'kvm_data'
        self.file_list = ['10.2.1.1', '10.2.1.2']
        self.per_file_seek = defaultdict()
        self.kvm_data = defaultdict()
        self.kvm_time = defaultdict()
        self.HashTable = ht.HashTable(self.file_list)
        self.must_data_len = 9

        self.kvm_file_name = "kvm_result"
        for file in self.file_list : 
            self.per_file_seek[file] = 0

    ###########################################
    # Match Time Func
    ###########################################
    def match_time_between_server(self) :
        for file in self.file_list:
            file_name = file + '_time'
            if os.path.isfile(self.folder_name + '/' + file_name) == False : return False
            fp = open(self.folder_name + '/' + file_name, 'r')
            line = fp.readline()
            fp.close()

            self.kvm_time[file] = line.split(' ')
        return True

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
    
    def server_diff_time(self, src_addr, dst_addr):
        src_addr = self.change_addr_to_str(src_addr)
        dst_addr = self.change_addr_to_str(dst_addr)
        
        boot_time = abs(int(self.kvm_time[src_addr][1]) - int(self.kvm_time[dst_addr][1]))
        cur_time = abs(int(self.kvm_time[src_addr][0]) - int(self.kvm_time[dst_addr][0]))
        
        return abs(boot_time - cur_time) 
    ###########################################
    # We need read thread to store log and calculate it
    ###########################################    
    def change_to_ctypes(self, ebpfdata) :
        if len(ebpfdata) != self.must_data_len : return None
        if int(ebpfdata[2]) != 167903489 and int(ebpfdata[2]) != 167903490 : return None
        if int(ebpfdata[3]) != 167903490 and int(ebpfdata[3]) != 167903489 : return None
        retval = dtype.ebpfData(ebpfdata)
        return retval

    def store_data_in_hashtable(self, ebpfdata):
        ebpfdata = self.change_to_ctypes(ebpfdata)
        if ebpfdata == None or ebpfdata.sent_bytes <= 0 : return
        key = self.HashTable.hash_function(ebpfdata.src_addr, ebpfdata.dst_addr, ebpfdata.src_port, ebpfdata.dst_port)
        self.HashTable.set_value(key, ebpfdata)

    def read_thread(self) :
        threshold = 100
        while True:
            for file in self.file_list:
                if os.path.isfile(self.folder_name + '/' + file + '_kvm') == False : continue
                fp = open(self.folder_name + '/' + file + '_kvm', 'r')
                fp.seek(self.per_file_seek[file], 0)
                
                line = fp.readline()
                cur_count = 0
                while line is not None :
                    ebpfdata = line.split(' ')
                    self.store_data_in_hashtable(ebpfdata)

                    self.per_file_seek[file] = fp.tell()
                    line = fp.readline()
                    cur_count += 1
                    if cur_count > threshold : break

                fp.close()

    ################################################
    # Here, We need to calculate by seq_num,
    # but event be missed ocassionally 
    # so we have to calculate carefully
    # ovs와는 다르게, 여기서는 seq_num을 기준으로 판단한다.
    # send를 기준으로 판단한다.
    # src_addr -> dst_addr, src_port -> dst_port, ts, sent_bytes를 저장한다.
    ################################################
    def calculate_thread(self) :
        threshold = 100
        while True :
            for key in list(self.HashTable.kvm_data.keys()) :
                fp = open(self.kvm_file_name, 'a')

                if self.HashTable.kvm_data[key].get(0) == None or self.HashTable.kvm_data[key].get(1) == None : continue
                elif self.HashTable.kvm_data[key][0].empty() or self.HashTable.kvm_data[key][1].empty() : continue

                send_ebpfdata = self.HashTable.kvm_data[key][0].get()

                while self.HashTable.kvm_data[key][1].empty() == False :
                    recv_ebpfdata = self.HashTable.kvm_data[key][1].get()
                    if send_ebpfdata.seq_num <= recv_ebpfdata.seq_num :
                        #print(send_ebpfdata.src_addr, send_ebpfdata.dst_addr, send_ebpfdata.src_port, send_ebpfdata.dst_port, send_ebpfdata.seq_num)
                        #print(recv_ebpfdata.src_addr, recv_ebpfdata.dst_addr, recv_ebpfdata.src_port, recv_ebpfdata.dst_port, recv_ebpfdata.seq_num)
                        #print(send_ebpfdata.ts, recv_ebpfdata.ts)
                        ts = abs(send_ebpfdata.ts - recv_ebpfdata.ts)
                        #print('ts = ', ts)
                        #print('diff ts = ', self.server_diff_time(int(send_ebpfdata.src_addr), int(send_ebpfdata.dst_addr)))
                        ts = abs(ts - self.server_diff_time(int(send_ebpfdata.src_addr), int(send_ebpfdata.dst_addr)))
                        #print(ts)
                        #print('-------------')
                        content = str(send_ebpfdata.src_addr) + ' ' + str(send_ebpfdata.dst_addr) + ' '
                        content += str(send_ebpfdata.src_port) + ' ' + str(send_ebpfdata.dst_port) + ' '
                        content += str(ts) + ' ' + str(send_ebpfdata.sent_bytes) + '\n'
                        fp.write(content)
                        
                        prev_seq_num = send_ebpfdata.seq_num
                        while self.HashTable.kvm_data[key][0].empty() == False and prev_seq_num == send_ebpfdata.seq_num :
                            send_ebpfdata = self.HashTable.kvm_data[key][0].get()
                        break
                fp.close()
    
    #################################################
    # threading start
    #################################################
    def start_function(self) :
        if self.match_time_between_server() == False :
            print('Please first bring server time to here')
            return

        read_thread = th.Thread(target = self.read_thread)
        read_thread.start()

        calculate_thread = th.Thread(target = self.calculate_thread)
        calculate_thread.start()

        read_thread.join()
        calculate_thread.join()
