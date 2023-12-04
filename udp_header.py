import struct

class UDPHeader:
    def __init__(self, src_port, dst_port, len, checksum):
        self.src_port = src_port
        self.dst_port = dst_port
        self.len = len
        self.checksum = checksum

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
        len = struct.unpack('BB', buffer)
        self.len_set(len)

    def get_checksum(self, buffer):
        checksum = struct.unpack('BB', buffer)
        self.checksum_set(checksum)
