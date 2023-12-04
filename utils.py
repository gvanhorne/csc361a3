from packet import Packet

def filtered_packet(packet: Packet) -> bool:
    return packet.ip_header.protocol != 17 and packet.ip_header.protocol != 1 and packet.datagram_header.src_port != 53 and packet.datagram_header.dst_port != 53
