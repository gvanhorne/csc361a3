import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from packet import Packet
from utils import filtered_packet
OS = 'linux'

def analyze_traceroute_windows(icmp_packets):
    icmp_value = None
    if len(icmp_packets):
        icmp_value = "1: ICMP"
    else:
        print(f"Error: No traceroute packets found")
        sys.exit(1)
    source_node = icmp_packets[0].ip_header.src_ip
    destination_node = icmp_packets[0].ip_header.dst_ip
    print(f"The IP Address of the source node: {source_node}")
    print(f"The IP Address of the ultimate destination node: {destination_node}")
    print(f"The IP Addresses of the intermediate destination nodes:")

    pairs = {}
    i = 1

    intermediate_router_ips = set()
    intermediate_routers = []

    for packet in icmp_packets:
        if packet.datagram_header.type == 8 and packet.ip_header.src_ip == source_node:
            seq_num = packet.datagram_header.seq_num
            pairs[seq_num] = {"request": packet}
    for packet in icmp_packets:
        if packet.datagram_header.icmp_copy and packet.datagram_header.type == 11 and pairs[packet.datagram_header.icmp_copy.seq_num]:
            if packet.ip_header.src_ip not in intermediate_router_ips:
                pairs[packet.datagram_header.icmp_copy.seq_num]["reply"] = packet
                intermediate_router_ips.add(packet.ip_header.src_ip)
    for pair in pairs:
        if len(pairs[pair]) > 1:
            print(f"    router {i}: {pairs[pair]['reply'].ip_header.src_ip}")
            i += 1
    print("\nThe values in protocol fields of IP headers:")
    if icmp_value:
        print(f"    {icmp_value}\n")

    fragments = []
    for packet1 in icmp_packets:
        matching_elements = 0
        offset = 0

        for packet2 in icmp_packets:
            if packet1.ip_header.id == packet2.ip_header.id:
                matching_elements += 1
                if packet2.ip_header.offset != 0 and packet2.ip_header.flags == 0:
                    offset = packet2.ip_header.offset

        if not any(entry["id"] == packet1.ip_header.id for entry in fragments):
            fragments.append({"id": packet1.ip_header.id, "num_frag": matching_elements, "offset": offset})
    fragments = sorted(fragments, key=lambda frag: frag['id'])
    for fragment in fragments:
        if fragment['id'] != 0:
            print(f"The number of fragments created from the original datagram with id {fragment['id']} is: {fragment['num_frag']}")
            print(f"The offset of the last fragment is: {fragment['offset']}\n")




    # for packet in icmp_packets:
    #     ip = packet.ip_header.src_ip
    #     if packet.ip_header.src_ip not in intermediate_router_ips:
    #         for pair in pairs:
    #             src_ip = packet.ip_header.src_ip
    #             seq_num = packet.datagram_header.seq_num
    #             dst_ip = packet.ip_header.dst_ip
    #             if pair['request'] and pair['request'].datagram_header.seq_num == seq_num:
    #                 pair['reply'] = packet
    #             elif pair['reply'] and pair['reply'].datagram_header.seq_num == seq_num:
    #                 pair['request'] = packet
    #     intermediate_router_ips.add(packet.datagram_header.ip_header_copy.src_ip)
    # for pair in pairs:
    #     if pair['reply']:
    #         print(f"    router {i}: {pair['request'].ip_header.dst_ip}")
    #     i += 1

def analyze_traceroute_linux(udp_packets, icmp_packets):
    if len(icmp_packets):
        icmp_value = "1: ICMP"
    if len(udp_packets):
        udp_value = "17: UDP"
        source_node = udp_packets[0].ip_header.src_ip
        destination_node = udp_packets[0].ip_header.dst_ip
    elif not len(udp_packets) and len(icmp_packets):
        source_node = icmp_packets[0].ip_header.src_ip
        destination_node = icmp_packets[0].ip_header.dst_ip
    else:
        print(f"Error: No traceroute packets found")
        sys.exit(1)
    print(f"The IP Address of the source node: {source_node}")
    print(f"The IP Address of the ultimate destination node: {destination_node}")
    print(f"The IP Addresses of the intermediate destination nodes:")
    pairs = []
    i = 1

    intermediate_router_ips = set()
    intermediate_routers = []
    for packet in udp_packets:
        src_ip = packet.ip_header.src_ip
        src_port = packet.datagram_header.src_port
        dst_ip = packet.ip_header.dst_ip
        dst_port = packet.datagram_header.dst_port
        pairs.append({"udp": packet, "icmp": None})
    for packet in icmp_packets:
        ip = packet.ip_header.src_ip
        if ip != source_node and ip != destination_node:
            if packet.ip_header.src_ip not in intermediate_router_ips:
                for pair in pairs:
                    src_ip = packet.ip_header.src_ip
                    src_port = packet.datagram_header.udp_copy.src_port
                    dst_ip = packet.ip_header.dst_ip
                    dst_port = packet.datagram_header.udp_copy.dst_port
                    if pair["udp"].ip_header.src_ip == dst_ip and pair["udp"].datagram_header.src_port == src_port and pair["udp"].datagram_header.dst_port == dst_port:
                        pair["icmp"] = packet
        intermediate_router_ips.add(packet.ip_header.src_ip)
    pairs = sorted(pairs, key=lambda pair: (pair["udp"].ip_header.ttl, pair["udp"].packet_No, pair["udp"].datagram_header.dst_port))
    for pair in pairs:
        if pair["icmp"]:
            print(f"    router {i}: {pair['icmp'].ip_header.src_ip}")
            i += 1

    print("\nThe values in protocol fields of IP headers:")
    if icmp_value:
        print(f"    {icmp_value}")
    if udp_value:
        print(f"    {udp_value}\n")

    fragments = []
    for packet1 in udp_packets:
        matching_elements = 0
        offset = 0

        for packet2 in udp_packets:
            if packet1.ip_header.id == packet2.ip_header.id:
                matching_elements += 1
                if packet2.ip_header.offset != 0 and packet2.ip_header.flags == 0:
                    offset = packet2.ip_header.offset

        if not any(entry["id"] == packet1.ip_header.id for entry in fragments):
            fragments.append({"id": packet1.ip_header.id, "num_frag": matching_elements, "offset": offset})
    fragments = sorted(fragments, key=lambda frag: frag['id'])
    for fragment in fragments:
        print(f"The number of fragments created from the original datagram with id {fragment['id']} is: {fragment['num_frag']}")
        print(f"The offset of the last fragment is: {fragment['offset']}\n")
    # print(f"The number of fragments created from the original datagram with id {packet.ip_header.identification} is: x")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_traceroute.py <tracefile>.cap")
        sys.exit(1)
    udp_packets = []
    icmp_packets = []
    tracefile = sys.argv[1]
    orig_time = 0
    num_packets = 0
    try:
        with open(tracefile, 'rb') as f:
            global_header_bytes = f.read(24)
            global_header = PCAPHeader.from_bytes(global_header_bytes)

            # Process individual packets
            while True:
                packet_header_bytes = f.read(16)

                if not packet_header_bytes:
                    break
                else:
                    packet_header = PacketHeader.from_bytes(packet_header_bytes, hex(global_header.magic_number))

                    # Read the packet data based on the "incl_len" from the packet header
                    packet_bytes = f.read(packet_header.incl_len)

                    # Create a Packet instance by parsing the packet data
                    packet = Packet.from_bytes(packet_bytes)
                    num_packets += 1

                    # Handle the timestamp for the packet
                    if orig_time == 0:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                        orig_time = packet_header.timestamp
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)
                    else:
                        packet_header.timestamp_set(packet_header_bytes[0:4], packet_header_bytes[4:8], orig_time)

                    # Set the packet's timestamp and add the connection to the list
                    if packet and not filtered_packet(packet, udp_packets):
                        packet.timestamp = packet_header.timestamp
                        packet.packet_No_set(num_packets)
                        if packet.ip_header.protocol == 17:
                            udp_packets.append(packet)
                        elif packet.ip_header.protocol == 1:
                            if packet.datagram_header.seq_num != 0 and OS == 'linux':
                                OS = 'windows'
                            icmp_packets.append(packet)

    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        if OS == 'linux':
            analyze_traceroute_linux(udp_packets, icmp_packets)
        else:
            analyze_traceroute_windows(icmp_packets)
