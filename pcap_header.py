import struct

class PCAPHeader:
    """
    Represents a PCAP global header.

    Attributes:
    - magic_number (int): The PCAP magic number.
    - version_major (int): Major version number of the PCAP file format.
    - version_minor (int): Minor version number of the PCAP file format.
    - thiszone (int): The timezone offset in seconds from UTC.
    - sigfigs (int): Timestamp accuracy in microseconds.
    - snaplen (int): The maximum number of bytes to capture per packet.
    - network (int): Link-layer header type.
    """

    def __init__(self, magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network):
        self.magic_number = magic_number
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.network = network

    def __str__(self):
        """
        Returns a string representation of the PCAPHeader object.
        """
        return (
            f"Magic Number: {hex(self.magic_number)}\n"
            f"Version Major: {self.version_major}\n"
            f"Version Minor: {self.version_minor}\n"
            f"Thiszone: {self.thiszone}\n"
            f"Sigfigs: {self.sigfigs}\n"
            f"Snaplen: {self.snaplen}\n"
            f"Network: {self.network}"
        )

    @classmethod
    def from_bytes(cls, header_bytes):
        if len(header_bytes) != 24:
            raise ValueError("Invalid global header length")
        magic_number = struct.unpack("<I", header_bytes[:4])[0]
        byte_order = ">" if magic_number == '0xa1b2c3d4' else "<"
        format_string = byte_order + "IHHIIII"
        values = struct.unpack(format_string, header_bytes)
        return cls(*values)