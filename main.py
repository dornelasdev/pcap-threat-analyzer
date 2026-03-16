from scapy.all import rdpcap, IP, TCP, UDP
import argparse
from collections import Counter
from detection_rules import detect_threats

GREEN = "\033[92m"
RESET = "\033[0m"

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    parsed_packets = []
    for index, packet in enumerate(packets, start=1):
        packet_record = {
            "packet_number": index,
            "timestamp": float(packet.time),
            "length": len(packet),
            "src_ip": None,
            "dst_ip": None,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
        }

        if IP in packet:
            packet_record["src_ip"] = packet[IP].src
            packet_record["dst_ip"] = packet[IP].dst

            if TCP in packet:
                packet_record["protocol"] = "TCP"
                packet_record["src_port"] = packet[TCP].sport
                packet_record["dst_port"] = packet[TCP].dport

            elif UDP in packet:
                packet_record["protocol"] = "UDP"
                packet_record["src_port"] = packet[UDP].sport
                packet_record["dst_port"] = packet[UDP].dport

            else:
                packet_record["protocol"] = "IP"

        parsed_packets.append(packet_record)

    return parsed_packets

def main():
    parser = argparse.ArgumentParser(description="PCAP parser v0.1")

    parser.add_argument("pcap_file", help="Path to the PCAP file")
    args = parser.parse_args()

    parsed_packets = parse_pcap(args.pcap_file)
    stats_result = compute_basic_stats(parsed_packets)
    print("No. of parsed packets:", len(parsed_packets))

    sections = [
        ("Protocol Counts", stats_result["protocol_counts"]),
        ("Top Source IPs", stats_result["top_src_ips"]),
        ("Top Destination Ports", stats_result["top_dst_ports"]),
    ]

    detections = detect_threats(parsed_packets)

    detection_sections = [
        ("Port Scan Findings", detections["port_scan"]),
        ("High Connection Volume", detections["high_connection_volume"]),
        ("DNS Query Findings", detections["dns_queries"]),
    ]

    for title, data in sections + detection_sections:
        print_section(title, data)

def compute_basic_stats(parsed_packets):
    proto_counter = Counter()
    srcip_counter = Counter()
    dport_counter = Counter()

    for record in parsed_packets:
        protocol = record["protocol"]
        src_ip = record["src_ip"]
        dst_port = record["dst_port"]

        proto_counter[protocol] += 1
        if src_ip is not None:
            srcip_counter[src_ip] += 1
        if dst_port is not None:
            dport_counter[dst_port] += 1

    c_stats = {
        "protocol_counts": dict(proto_counter),
        "top_src_ips": dict(srcip_counter.most_common(5)),
        "top_dst_ports": dict(dport_counter.most_common(5)),
    }
    return c_stats

def print_section(title, data):

    print(f"\n{GREEN}{title}{RESET}")
    print("-" * len(title))

    if not data:
        print("No data")
        return

    if isinstance(data, dict):
        for key, value in data.items():
            print(f"{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            print(item)
    else:
        print(data)

if __name__ == "__main__":
    main()
