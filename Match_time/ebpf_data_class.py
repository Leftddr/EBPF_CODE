import ctypes

class ebpfData(ctypes.Structure) :
    _fields_ = [('src_addr', ctypes.c_uint), ('dst_addr', ctypes.c_uint), ('ts', ctypes.c_ulong)]