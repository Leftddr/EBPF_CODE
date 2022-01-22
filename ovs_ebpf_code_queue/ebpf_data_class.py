import ctypes

EVENT_BATCH = 10

class ebpfData(ctypes.Structure) :
    _fields_ = [('src_addr', ctypes.c_uint), ('dst_addr', ctypes.c_uint), \
    ('src_port', ctypes.c_ushort), ('dst_port', ctypes.c_ushort), ('ts', ctypes.c_ulong), ('pkt_len', ctypes.c_ulong), ('e_count', ctypes.c_ulong), \
    ('sent_seq', ctypes.c_uint), ('recv_ack', ctypes.c_uint), ('evt_type', ctypes.c_char)]

class ebpfDataBatch(ctypes.Structure) :
    _fields_ = [('arr', ebpfData * EVENT_BATCH)]
