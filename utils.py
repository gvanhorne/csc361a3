def filtered_packet(packet) -> bool:
    # add protocol 1 when ready
    return packet.ip_header.protocol != 17 or (packet.datagram_header.src_port == 53 or packet.datagram_header.dst_port == 53)

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
