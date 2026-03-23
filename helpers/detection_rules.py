from collections import defaultdict
from collections import Counter

PORT_SCAN_THRESHOLD = 20
HIGH_CONNECTION_VOLUME_THRESHOLD = 10
DNS_UNIQUE_QUERY_THRESHOLD = 5

def detect_threats(parsed_packets):
    detections = {
        "port_scan": [],
        "high_connection_volume": [],
        "dns_queries": []
    }

    src_to_ports = defaultdict(set)

    for record in parsed_packets:
        src_ip = record["src_ip"]
        dst_port = record["dst_port"]

        if src_ip is not None and dst_port is not None:
            src_to_ports[src_ip].add(dst_port)

    for src_ip, ports_set in src_to_ports.items():
        if len(ports_set) >= PORT_SCAN_THRESHOLD:
            detections["port_scan"].append({
                "src_ip": src_ip,
                "unique_dst_ports": len(ports_set),
            })


    src_ip_counter = Counter()

    for record in parsed_packets:
        src_ip = record["src_ip"]
        if src_ip is not None:
            src_ip_counter[src_ip] += 1

    for src_ip, packet_count in src_ip_counter.items():
        if packet_count >= HIGH_CONNECTION_VOLUME_THRESHOLD:
            detections["high_connection_volume"].append({
                "src_ip": src_ip,
                "packet_count": packet_count,
            })

    dns_queries_by_src_ip = defaultdict(set)

    for record in parsed_packets:
        src_ip = record.get("src_ip")
        dns_query = record.get("dns_query")

        if src_ip is not None and dns_query:
            dns_queries_by_src_ip[src_ip].add(dns_query)

    for src_ip, query_set in dns_queries_by_src_ip.items():
        if len(query_set) >= DNS_UNIQUE_QUERY_THRESHOLD:
            detections["dns_queries"].append({
                "rule": "high_unique_dns_queries",
                "severity": "medium",
                "reason": f"{len(query_set)} unique DNS queries from one source",
                "src_ip": src_ip,
                "unique_dns_queries": len(query_set),
                "sample_queries": sorted(list(query_set))[:5],
            })

    return detections
