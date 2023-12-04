import struct

class EthernetHeader:
    """
    Represents an Ethernet header.

    Attributes:
    - dest_mac (bytes): Destination MAC address.
    - source_mac (bytes): Source MAC address.
    - eth_type (int): Ethernet frame type.

    Methods:
    - __init__(self, dest_mac, source_mac, eth_type): Initializes an EthernetHeader object with the provided values.
    - __str__(self): Returns a string representation of the EthernetHeader object.
    - from_bytes(cls, bytes): Creates an EthernetHeader object from a byte sequence.
      - Parameters:
        - cls (class): The class to create an instance of.
        - bytes (bytes): The byte sequence containing Ethernet header data.
      - Returns:
        - EthernetHeader: An EthernetHeader object representing the parsed header data.
    """
    def __init__(self, dest_mac, source_mac, eth_type):
        self.dest_mac = dest_mac
        self.source_mac = source_mac
        self.eth_type = eth_type

    def __str__(self):
        """
        Returns a string representation of the EthernetHeader object.
        """
        return f"Destination MAC Address: {self.dest_mac.hex(':')}\n" \
               f"Source MAC Address: {self.source_mac.hex(':')}\n" \
               f"Ethernet Type: {hex(self.eth_type)}"

    @classmethod
    def from_bytes(cls, bytes):
        """
        Create an EthernetHeader object from a byte sequence.

        Parameters:
        - cls (class): The class to create an instance of.
        - bytes (bytes): The byte sequence containing Ethernet header data.

        Returns:
        - EthernetHeader: An EthernetHeader object representing the parsed header data.
        """
        dest_mac, source_mac, eth_type = struct.unpack("!6s6sH", bytes)
        return cls(dest_mac, source_mac, eth_type)
