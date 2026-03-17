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

    sections = [
        ("Protocol Counts", report["stats"]["protocol_counts"]),
        ("Top Source IPs", report["stats"]["top_src_ips"]),
        ("Top Destination Ports", report["stats"]["top_dst_ports"]),
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
        for item in data:
            print(item)
    else:
        print(data)
