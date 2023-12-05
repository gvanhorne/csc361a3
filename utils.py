def filtered_packet(packet, udp_packets) -> bool:
    types = [0, 3, 8, 11]
    if packet.ip_header.protocol == 1:
        type = packet.datagram_header.type
        if type not in types:
            return True
        return False
    elif packet.ip_header.protocol == 17:
        if packet.ip_header.flags != 0:
            return False
        for f in udp_packets:
            if f.ip_header.id == packet.ip_header.id:
                return False
        if not (packet.datagram_header.dst_port >= 33434 and packet.datagram_header.dst_port <= 33529):
            return True

def get_byte_order(magic_number):
    if magic_number == '0xa1b2c3d4':
        return "<"
    elif magic_number == '0xd4c3b2a1':
        return ">"
    elif magic_number == '0xa1b23c4d':
        return "<"
    elif magic_number == '0x4d3cb2a1':
        return ">"
    else:
        raise ValueError("Invalid magic number")
