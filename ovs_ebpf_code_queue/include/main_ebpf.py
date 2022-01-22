import threading
import ebpf_c_code as ebpfcc
#import ebpf_python_code as ebpfpy

if __name__ == "__main__" :
    ebpfc = ebpfcc.ebpfCode()
    #ebpfpython = ebpfPythonCode()

    prog = ebpfc.make_complete_code()
    
    #ebpfpython.attach_code(prog)
    #ebpfpython.attach_event()
