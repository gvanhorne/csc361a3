import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from packet import Packet
from utils import filtered_packet

def analyze_traceroute(udp_packets, icmp_packets):
    print(udp_packets)
    pairs = []

    for packet in udp_packets:
        src_ip = packet.ip_header.src_ip
        src_port = packet.datagram_header.src_port
        dst_ip = packet.ip_header.dst_ip
        dst_port = packet.datagram_header.dst_port
    for packet in icmp_packets:
        print(packet.packet_No)

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
                    if packet and not filtered_packet(packet):
                        packet.timestamp = packet_header.timestamp
                        packet.packet_No_set(num_packets)
                        if not packet.icmp_message:
                            udp_packets.append(packet)
                        else:
                            icmp_packets.append(packet)

    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        analyze_traceroute(udp_packets, icmp_packets)
