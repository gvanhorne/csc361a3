import struct

class ICMPHeader:
    def __init__(self):
        self.type = None
        self.code = None
        self.checksum = None
        self.rest = None
        self.ip_header_copy = None
        self.udp_copy = None

    def set_type(self, type):
        self.type = type

    def set_code(self, code):
        self.code = code

    def set_checksum(self, checksum):
        self.checksum = checksum

    def set_rest_of_header(self, rest):
        self.rest = rest

    def set_ip_header_copy(self, ip_header_copy):
        self.ip_header_copy = ip_header_copy

    def set_udp_copy(self, udp_copy):
        self.udp_copy = udp_copy

    def get_type(self, buffer):
        type = struct.unpack('B', buffer)[0]
        self.set_type(type)

    def get_code(self, buffer):
        code = struct.unpack('B', buffer)[0]
        self.set_code(code)

    def get_checksum(self, buffer):
        checksum = struct.unpack('>H', buffer)[0]
        self.set_checksum(checksum)

    def get_rest_of_header(self, buffer):
        rest_of_header = struct.unpack('>HH', buffer)[1]
        self.set_rest_of_header(rest_of_header)
