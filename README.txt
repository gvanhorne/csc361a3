# CSC 361 Assignment 3

## Overview
`analyze_traceroute.py` is a Python program designed to analyze traceroute information stored in a pcap (Packet Capture) file. The program extracts and displays key details such as the IP address of the source node, the IP address of the ultimate destination node, the IP address of each intermediate destination node, and the fragmentation (if any) of each datagram.

## Requirements
- Python 3.x

## Installation
1. Make sure you have Python 3.x installed. If not, you can download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).

## Running the Program
Navigate to the directory containing analyze_traceroute.py and execute the following command from the command line:

```bash
python analyze_traceroute.py <path_to_file>.pcap
```
Replace <path_to_file>.pcap with the actual path to your pcap file.

Output
The program will return information about the traceroute, including:

IP address of the source node
IP address of the ultimate destination node
IP address of each intermediate destination node
Fragmentation details (if any) for each datagram
Example
```bash
python analyze_traceroute.py example.pcap
```
Notes
Ensure that the pcap file contains traceroute information.
Both windows and linux pcap file captures are supported.
