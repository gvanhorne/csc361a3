import struct
class UDPHeader:
    def __init__(self):
        self.src_port = None
        self.dst_port = None
        self.len = 0
        self.checksum = None
        self.data_offset = 0
        self.byte_order = 0

    def set_data_offset(self):
        self.data_offset = self.len * 8

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self,dst):
        self.dst_port = dst

    def len_set(self, len):
        self.len = len

    def checksum_set(self, checksum):
        self.checksum = checksum

    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None

    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None

    def get_len(self, buffer):
        length = struct.unpack(f'>H', buffer)
        self.len_set(length[0])

    def get_checksum(self, buffer):
        checksum = struct.unpack(f'>H', buffer)
        self.checksum_set(checksum[0])
