from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR
import argparse
import os
import time
from typing import Any, Dict, List
from collections import Counter
from helpers.detection_rules import detect_threats
from helpers.reporting import build_report, render_text_report, render_json


def parse_pcap(file_path: str) -> List[Dict[str, Any]]:
    """Parse a PCAP file into normalized packet records"""

    parsed_packets = []
    with PcapReader(file_path) as packets:
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

def main() -> None:
    """CLI entry point for parsing, detection, and report output."""

    parser = argparse.ArgumentParser(description="PCAP threat analyzer CLI")

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
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=40,
        help="Unique destination ports threshold for port-scan detection (default: 40)",
    )
    parser.add_argument(
        "--hcv-threshold",
        type=int,
        default=300,
        help="Packet count threshold for high connection volume detection (default: 300)",
    )
    parser.add_argument(
        "--dns-unique-threshold",
        type=int,
        default=12,
        help="Unique DNS queries threshold per source IP (default: 12)",
    )

    parser.add_argument(
        "--detail",
        choices=["compact", "full"],
        default="full",
        help="Report detail level: compact or full (default: full)",
    )

    args = parser.parse_args()

    threshold_checks = [
        ("--port-scan-threshold", args.port_scan_threshold),
        ("--hcv-threshold", args.hcv_threshold),
        ("--dns-unique-threshold", args.dns_unique_threshold),
    ]

    for name, value in threshold_checks:
        if value < 1:
            parser.error(f"{name} must be >= 1")

    pipeline_start = time.perf_counter()

    try:
        parse_start = time.perf_counter()
        parsed_packets = parse_pcap(args.pcap_file)
        parse_duration = time.perf_counter() - parse_start
    except FileNotFoundError:
        parser.error(f"PCAP file not found: {args.pcap_file}")
    except PermissionError:
        parser.error(f"Permission denied when reading: {args.pcap_file}")
    except Exception as exc:
        parser.error(f"Failed to parse PCAP file '{args.pcap_file}': {exc}")

    safe_duration = max(parse_duration, 1e-6)
    packet_count = len(parsed_packets)
    packets_per_second = packet_count / safe_duration
    total_pipeline_duration = time.perf_counter() - pipeline_start

    runtime_metrics = {
        "parse_duration_seconds": round(safe_duration, 6),
        "total_pipeline_seconds": round(max(total_pipeline_duration, 1e-6), 6),
        "packet_count": packet_count,
        "packets_per_second": round(packets_per_second, 2)
    }

    stats_result = compute_basic_stats(parsed_packets)
    detections = detect_threats(parsed_packets, args.port_scan_threshold, args.hcv_threshold, args.dns_unique_threshold)
    report = build_report(parsed_packets, stats_result, detections, runtime_metrics)

    if args.output == "json":
        output_content = render_json(report)
    else:
        output_content = render_text_report(report, detail=args.detail, to_string=True)

    if args.output_file:
        output_path = args.output_file

        if args.output == "json" and not output_path.lower().endswith(".json"):
            output_path += ".json"
        if args.output == "text" and not output_path.lower().endswith(".txt"):
            output_path += ".txt"

        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_content)

        print(f"Report saved to: {output_path}")
    else:
        if args.output == "text":
            render_text_report(report, detail=args.detail, to_string=False)
        else:
            print(output_content)


def compute_basic_stats(parsed_packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute baseline traffic and DNS statistics from parsed packet records."""

    proto_counter = Counter()
    src_ip_counter = Counter()
    dport_counter = Counter()
    dns_query_counter = Counter()

    for record in parsed_packets:
        protocol = record["protocol"]
        src_ip = record["src_ip"]
        dst_port = record["dst_port"]
        dns_query = record.get("dns_query")

        proto_counter[protocol] += 1
        if src_ip is not None:
            src_ip_counter[src_ip] += 1
        if dst_port is not None:
            dport_counter[dst_port] += 1
        if dns_query:
            dns_query_counter[dns_query] += 1

    stats_result = {
        "protocol_counts": dict(proto_counter),
        "top_src_ips": dict(src_ip_counter.most_common(5)),
        "top_dst_ports": dict(dport_counter.most_common(5)),
        "dns_query_count": sum(dns_query_counter.values()),
        "top_dns_queries": dict(dns_query_counter.most_common(5)),
    }
    return stats_result

if __name__ == "__main__":
    main()
