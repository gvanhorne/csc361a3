from ip_header import IPHeader
from udp_header import UDPHeader
from icmp_header import ICMPHeader
from ethernet_header import EthernetHeader

class Packet():
    #pcap_hd_info = None
    ip_header = None
    tcp_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    data_bytes = 0


    def __init__(self, ip_header, datagram_header, packet_bytes):
        self.ip_header = ip_header
        self.datagram_header = datagram_header
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.data_bytes = len(packet_bytes[14 + ip_header.ip_header_len + datagram_header.data_offset:]
            .rstrip(b'\x00'))

    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)

    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)

    @classmethod
    def from_bytes(cls, packet_bytes):
        ethernet_bytes = packet_bytes[:14]
        ethernet_header = EthernetHeader.from_bytes(ethernet_bytes)

        ip_header = IPHeader()
        ip_header.get_header_len(packet_bytes[14:15])
        ip_header.get_total_len(packet_bytes[16:18])
        ip_header_bytes = packet_bytes[14:14+ip_header.ip_header_len]
        protocol = ip_header.get_protocol(packet_bytes[23:24])
        ip_header.get_IP(packet_bytes[26:30], packet_bytes[30:34])
        if ip_header.protocol == 17:
            header = UDPHeader()
            offset = 14+ip_header.ip_header_len
            header.get_src_port(packet_bytes[offset:offset + 2])
            header.get_dst_port(packet_bytes[offset + 2:offset + 4])
            header.get_len(packet_bytes[offset + 4:offset + 6])
            header.get_checksum(packet_bytes[offset + 6:offset + 8])
            header.set_data_offset()
        elif ip_header.protocol == 1:
            header = ICMPHeader()
            offset = 14+ip_header.ip_header_len
            header.get_type(packet_bytes[offset:offset + 1])
            header.get_code(packet_bytes[offset + 1: offset + 2])
            header.get_checksum(packet_bytes[offset + 2: offset + 4])
        else:
            return
        return cls(ip_header, header, packet_bytes)
