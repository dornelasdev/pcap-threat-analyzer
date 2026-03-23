import json

GREEN = "\033[92m"
RESET = "\033[0m"

def build_report(parsed_packets, stats_result, detections):
    return {
        "summary": {
            "total_packets": len(parsed_packets)
        },
        "stats": stats_result,
        "detections": detections
    }

def render_text_report(report):

    print("No. of parsed packets:", report["summary"]["total_packets"])
    print("DNS queries extracted:", report["stats"]["dns_query_count"])

    sections = [
        ("Protocol Counts", report["stats"]["protocol_counts"]),
        ("Top Source IPs", report["stats"]["top_src_ips"]),
        ("Top Destination Ports", report["stats"]["top_dst_ports"]),
        ("Top DNS Queries", report["stats"]["top_dns_queries"])
    ]
    detection_sections = [
        ("Port Scan Findings", report["detections"]["port_scan"]),
        ("High Connection Volume", report["detections"]["high_connection_volume"]),
        ("DNS Query Findings", report["detections"]["dns_queries"]),

    ]

    for title, data in sections + detection_sections:
        print_section(title, data)

def render_json(report):
    return json.dumps(report, indent=2)

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
        for i, item in enumerate(data, start=1):
            if isinstance(item, dict):
                rule = item.get("rule", "unknown_rule")
                severity = item.get("severity", "N/A")
                reason = item.get("reason", "N/A")
                src_ip = item.get("src_ip", "N/A")
                print(f"{i}. [{severity}] {rule} | src={src_ip} | {reason}")

                if "unique_dst_ports" in item:
                    print(f"   unique_dst_ports: {item['unique_dst_ports']}")
                if "packet_count" in item:
                    print(f"   packet_count: {item['packet_count']}")
                if "unique_dns_queries" in item:
                    print(f"   unique_dns_queries: {item['unique_dns_queries']}")
                if "sample_queries" in item:
                    print(f"   sample_queries: {', '.join(item['sample_queries'])}")
            else:
                print(f"{i}. {item}")

