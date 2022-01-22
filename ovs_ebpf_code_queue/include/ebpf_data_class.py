import ctypes

EVENT_BATCH = 5

class ebpfData(ctypes.Structure) :
    _fields_ = [('src_addr', ctypes.c_uint), ('dst_addr', ctypes.c_uint), \
    ('src_port', ctypes.c_ushort), ('dst_port', ctypes.c_ushort), ('ts', ctypes.c_ulong), ('pkt_len', ctypes.c_ulong), ('e_count', ctypes.c_ulong)]

class ebpfDataBatch(ctypes.Structure) :
    _fields_ = [('arr', ebpfData * EVENT_BATCH)]