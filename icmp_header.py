import struct

class ICMPHeader:
    def __init__(self):
        self.type = None
        self.code = None
        self.checksum = None

    def set_type(self, type):
        self.type = type

    def set_code(self, code):
        self.code = code

    def set_checksum(self, checksum):
        self.checksum = checksum

    def get_type(self, buffer):
        type = struct.unpack('B', buffer)[0]
        self.set_type(type)

    def get_code(self, buffer):
        code = struct.unpack('B', buffer)[0]
        self.set_code(code)

    def get_checksum(self, buffer):
        checksum = struct.unpack('>H', buffer)[0]
        self.set_checksum(checksum)
