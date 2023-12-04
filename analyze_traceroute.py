import sys
from pcap_header import PCAPHeader
from packet_header import PacketHeader
from packet import Packet
from connection import Connection
from utils import filtered_packet

def analyze_traceroute(connections):
    source_node = connections[0].src_ip
    destination_node = connections[0].dst_ip
    print(f"The IP address of the source node: {source_node}")
    print(f"The IP address of the ultimate destination node: {destination_node}")
    print(f"The IP addresses of intermediate nodes:")
    i = 1
    intermediate_nodes = set()
    for connection in connections:
        intermediate_nodes.add(connection.src_ip)
    intermediate_nodes.remove(source_node)
    intermediate_nodes.remove(destination_node)
    for node in intermediate_nodes:
        print(f"router {i}: {node}")
        i += 1
    return

def update_duration_stats(duration, min_duration, max_duration, sum_duration):
    """
    Update duration statistics.

    Args:
        duration (float): Duration value to be updated.
        min_duration (float): Minimum duration value.
        max_duration (float): Maximum duration value.
        sum_duration (float): Sum of duration values.

    Returns:
        tuple: Updated min_duration, max_duration, and sum_duration.
    """
    new_min_duration = min(min_duration, duration)
    new_max_duration = max(max_duration, duration)
    new_sum_duration = sum_duration + duration
    return new_min_duration, new_max_duration, new_sum_duration


def update_rtt_stats(connection, min_rtt, max_rtt, rtts):
    """
    Update RTT (Round-Trip Time) statistics.

    Args:
        connection (Connection): The Connection object to get RTT information from.
        min_rtt (float): Minimum RTT value.
        max_rtt (float): Maximum RTT value.
        rtts (list): List of RTT values.

    Returns:
        tuple: Updated min_rtt, max_rtt, and rtts.
    """
    new_min_rtt = min(min_rtt, connection.get_min_rtt())
    new_max_rtt = max(max_rtt, connection.max_RTT)
    new_rtts = rtts + connection.get_rtts()
    return new_min_rtt, new_max_rtt, new_rtts

def update_packet_stats(connection, min_packets, max_packets, sum_packets):
    """
    Update packet statistics.

    Args:
        connection (Connection): The Connection object to get packet information from.
        min_packets (int): Minimum number of packets.
        max_packets (int): Maximum number of packets.
        sum_packets (int): Sum of packet counts.

    Returns:
        tuple: Updated min_packets, max_packets, and sum_packets.
    """
    num_packets = connection.num_packets_to_src + connection.num_packets_to_dst
    new_min_packets = min(min_packets, num_packets)
    new_max_packets = max(max_packets, num_packets)
    new_sum_packets = sum_packets + num_packets
    return new_min_packets, new_max_packets, new_sum_packets

def add_connection(packet, connections):
    """
    Adds a connection tuple to the connections set if it and the reverse connection are not already present.

    Args:
        packet: The packet containing connection information.
        connections: The set of connections to which the new connection should be added.

    Returns:
        None
    """
    if packet.icmp_message:
        src_port = packet.datagram_header.udp_copy.src_port
        dst_port = packet.datagram_header.udp_copy.dst_port
    else:
        src_port = packet.datagram_header.src_port
        dst_port = packet.datagram_header.dst_port
    packet_connection = Connection(
        packet.ip_header.src_ip,
        src_port,
        packet.ip_header.dst_ip,
        dst_port
    )

    existing_connection = next((conn for conn in connections if conn == packet_connection), None)
    if existing_connection:
        existing_connection.add_packet(packet)
    else:
        # No matching connection, so append to the list of collections
        packet_connection.connection_src = packet.ip_header.src_ip
        packet_connection.connection_dst = packet.ip_header.dst_ip
        packet_connection.add_packet(packet)
        connections.append(packet_connection)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_traceroute.py <tracefile>.cap")
        sys.exit(1)
    connections = []
    tracefile = sys.argv[1]
    orig_time = 0
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
                        add_connection(packet, connections)

    except IOError:
        print("Could not read file:", tracefile)
    finally:
        f.close()
        analyze_traceroute(connections)
