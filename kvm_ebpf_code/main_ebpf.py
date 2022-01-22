import ebpf_c_code as ebpfcc
import ebpf_python_code as ebpfpypy

if __name__ == "__main__":
    kernel_func = ["sock_sendmsg", "dev_queue_xmit", "sock_recvmsg", "tcp_v4_rcv"]
    ebpfc = ebpfcc.ebpfCode(kernel_func)
    prog = ebpfc.make_complete_code()


    ebpfpy = ebpfpypy.ebpfPythonCode(prog, kernel_func, "ovs_file", "kvm_file")
    ebpfpy.start_function()       
