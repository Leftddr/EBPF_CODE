import threading
import ebpf_c_code as ebpfcc
import ebpf_python_code as ebpfpy
import threading

if __name__ == "__main__" :
    ebpfc = ebpfcc.ebpfCode()

    prog = ebpfc.make_complete_code()
    ebpfpython = ebpfpy.ebpfPythonCode(prog)

    fp = open('code.txt', 'w')
    fp.write(prog)
    fp.close()
    ebpfpython.start_function()
