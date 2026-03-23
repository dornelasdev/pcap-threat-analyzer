from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
import argparse
import os
from collections import Counter
from helpers.detection_rules import detect_threats
from helpers.reporting import build_report, render_text_report, render_json

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
            "dns_query": None,
            "dns_qtype": None,
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

            if DNS in packet and packet[DNS].qd is not None:
                qname = packet[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="ignore")
                packet_record["dns_query"] = qname.rstrip(".")
                packet_record["dns_qtype"] = packet[DNSQR].qtype

        parsed_packets.append(packet_record)

    return parsed_packets

def main():
    parser = argparse.ArgumentParser(description="PCAP parser v0.4")

    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument(
        "-o", "--output",
        choices=["json", "text"],
        help="Output format: text(default) or json",
        default="text"
    )
    parser.add_argument(
        "-f", "--output-file",
        help="Optional file path to save output",
        default=None
    )

    args = parser.parse_args()

    parsed_packets = parse_pcap(args.pcap_file)
    stats_result = compute_basic_stats(parsed_packets)
    detections = detect_threats(parsed_packets)
    report = build_report(parsed_packets, stats_result, detections)

    if args.output == "json":
        output_content = render_json(report)

        if args.output_file:
            output_path = args.output_file
        else:
            output_path = "outputs/report.json"

        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_content)

        print(f"Report saved to: {output_path}")
    else:
        render_text_report(report)


def compute_basic_stats(parsed_packets):
    proto_counter = Counter()
    srcip_counter = Counter()
    dport_counter = Counter()
    dns_query_counter = Counter()

    for record in parsed_packets:
        protocol = record["protocol"]
        src_ip = record["src_ip"]
        dst_port = record["dst_port"]
        dns_query = record.get("dns_query")

        proto_counter[protocol] += 1
        if src_ip is not None:
            srcip_counter[src_ip] += 1
        if dst_port is not None:
            dport_counter[dst_port] += 1
        if dns_query:
            dns_query_counter[dns_query] += 1

    c_stats = {
        "protocol_counts": dict(proto_counter),
        "top_src_ips": dict(srcip_counter.most_common(5)),
        "top_dst_ports": dict(dport_counter.most_common(5)),
        "dns_query_count": sum(dns_query_counter.values()),
        "top_dns_queries": dict(dns_query_counter.most_common(5)),
    }
    return c_stats

if __name__ == "__main__":
    main()
