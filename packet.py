from ip_header import IPHeader
from tcp_header import TCPHeader
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
    
    
    def __init__(self, ip_header, tcp_header, packet_bytes):
        self.ip_header = ip_header
        self.tcp_header = tcp_header
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.data_bytes = len(packet_bytes[14 + ip_header.ip_header_len + tcp_header.data_offset:]
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
        ip_header.get_IP(packet_bytes[26:30], packet_bytes[30:34])

        tcp_header = TCPHeader()
        tcp_header.get_data_offset(packet_bytes[14+ip_header.ip_header_len + 12:14+ip_header.ip_header_len + 13])
        tcp_header_bytes = packet_bytes[14+ip_header.ip_header_len:14+ip_header.ip_header_len+tcp_header.data_offset]
        tcp_header.get_src_port(packet_bytes[14+ip_header.ip_header_len:14+ip_header.ip_header_len + 2])
        tcp_header.get_dst_port(packet_bytes[14+ip_header.ip_header_len + 2:14+ip_header.ip_header_len + 4])
        tcp_header.get_flags(packet_bytes[14+ip_header.ip_header_len + 13:14+ip_header.ip_header_len + 14])
        if (tcp_header.flags["ACK"] == 1):
            tcp_header.get_ack_num(packet_bytes[14+ip_header.ip_header_len + 8:14+ip_header.ip_header_len + 12])
        tcp_header.get_seq_num(packet_bytes[14+ip_header.ip_header_len + 4:14+ip_header.ip_header_len + 8])
        tcp_header.get_window_size(packet_bytes[14+ip_header.ip_header_len + 14:14+ip_header.ip_header_len + 15],
                                    packet_bytes[14+ip_header.ip_header_len + 15:14+ip_header.ip_header_len + 16])
        return cls(ip_header, tcp_header, packet_bytes)