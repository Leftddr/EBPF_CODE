#########################################################
# Application for send packet to other server
# 임의로 함수를 실행시켜서 패킷을 전달시킨다.
#########################################################
from bcc import BPF
import socket
import time
import multiprocessing
from collections import defaultdict

class ebfpSocket:
    def __init__(self, prog):
        self.prog = prog
        self.b = BPF(text = prog, cflags = ['-std=gnu99', '-DNUM_CPUS=%d' % multiprocessing.cpu_count()])
        self.my_server_addr = '10.2.1.1'
        self.server_list = ['10.2.1.1', '10.2.1.2']
        self.server_port = 5999

        self.event_name = 'send_time'
        self.file_name = 'server_diff_time'

        self.multi_num = 1000000000
        self.server_diff_time = defaultdict()

    ######################################################
    # event을 받았는지 확인한다.
    ######################################################
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

    def isICMP_event(self, cpu, data, size) :
        event = self.b[self.event_name].event(data)
        src_addr = self.change_addr_to_str(event.s_addr)
        dst_addr = self.change_addr_to_str(event.d_addr)
        self.server_diff_time[src_addr + dst_addr] = event.ts
        self.server_diff_time[dst_addr + src_addr] = event.ts
    ######################################################
    # ping to another server
    ######################################################
    # Client server
    def socket_send_thread(self):
        data = str(time.time() * self.multi_num)
        for server_addr in self.server_list:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((server_addr, self.server_port))
            server_socket.listen()
            # client_socket, addr = server_socket.accept()
            print('Connect by', addr)

            client_socket.close()
            server_socket.close()
    
    # Management server
    def socket_recv_thread(self):
        prev_time = time.time()
        time_threshold = 10
        while True :
            need_to_loop = False
            if time.time() - prev_time > time_threshold : return False 
            for server_addr in self.server_list:
                ## 의미 없는 데이터라도 집어넣어서 보낸다.
                if (self.my_server_addr + server_addr) in list(self.server_diff_time.keys()) : continue
                need_to_loop = True
                data = str(time.time() * self.multi_num)
                client_socket = socket.socket(socket.AF_INET, sock.SOCK_STREAM)
                client_socket.connet((server_addr, self.server_port))
                client_socket.sendall(data.encode())
                client_socket.close()
            if need_to_loop == False : break
        
        try:
            fp = open(self.file_name, 'w')
            for server_addr in self.server_list:
                ts = self.server_diff_time[self.my_server_addr + server_addr]
                fp.write(self.my_server_addr + ' ' + server_addr + ' ' + str(ts))
            fp.close()
        except:
            return False
        return True
        
    
