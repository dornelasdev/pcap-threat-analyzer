from contextlib import redirect_stdout
from io import StringIO
import json
from typing import List, Dict, Any
from collections import Counter

GREEN = "\033[92m"
RESET = "\033[0m"

def build_report(
    parsed_packets: List[Dict[str, Any]],
    stats_result: Dict[str, Any],
    detections: Dict[str, List[Dict[str, Any]]],
    runtime_metrics: Dict[str, Any]
) -> Dict[str, Any]:
    """Assemble the final report object."""

    return {
        "summary": {
            "total_packets": len(parsed_packets),
            "detection_summary": build_detection_summary(detections),
            "runtime_metrics": runtime_metrics,
        },
        "stats": stats_result,
        "detections": detections
    }


def render_text_report_impl(report: Dict[str, Any], detail: str = "full") -> None:
    """Render a human-readable report to terminal output."""

    print("No. of parsed packets:", report["summary"]["total_packets"])
    print("DNS queries extracted:", report["stats"]["dns_query_count"])
    print("Total findings:", report["summary"]["detection_summary"]["total_findings"])
    metrics = report["summary"]["runtime_metrics"]
    print(
        f"Parse: {metrics['parse_duration_seconds']}s | "
        f"Total: {metrics['total_pipeline_seconds']}s | "
        f"Packets: {metrics['packet_count']} | "
        f"Rate: {metrics['packets_per_second']} pkt/s"
    )

    if detail == "compact":
        compact_sections = [
            ("Findings by Severity", report["summary"]["detection_summary"]["by_severity"]),
            ("Findings by Rule", report["summary"]["detection_summary"]["by_rule"]),
        ]
        for title, data in compact_sections:
            print_section(title, data)
        return

    sections = [
        ("Protocol Counts", report["stats"]["protocol_counts"]),
        ("Top Source IPs", report["stats"]["top_src_ips"]),
        ("Top Destination Ports", report["stats"]["top_dst_ports"]),
        ("Top DNS Queries", report["stats"]["top_dns_queries"]),
        ("Findings by Severity", report["summary"]["detection_summary"]["by_severity"]),
        ("Findings by Rule", report["summary"]["detection_summary"]["by_rule"])
    ]
    detection_sections = [
        ("Port Scan Findings", report["detections"]["port_scan"]),
        ("High Connection Volume", report["detections"]["high_connection_volume"]),
        ("DNS Query Findings", report["detections"]["dns_queries"]),
    ]
    for title, data in sections + detection_sections:
        print_section(title, data)

def render_text_report(
        report: Dict[str, Any],
        detail: str = "full",
        to_string: bool = False,
) -> str | None:
    if not to_string:
        render_text_report_impl(report, detail=detail)
        return None

    buffer = StringIO()
    with redirect_stdout(buffer):
        render_text_report_impl(report, detail=detail)
        return buffer.getvalue()

def render_json(report: Dict[str, Any]) -> str:
    """Serialize report data to pretty-printed JSON."""

    return json.dumps(report, indent=2)

def print_section(title: str, data: Any) -> None:
    """Print one report section in a readable format."""

    print(f"\n{GREEN}{title}{RESET}")
    print("-" * len(title))

    if not data:
        print("No data")
        return

    if isinstance(data, dict):
        for key in sorted(data, key=lambda k: str(k)):
            print(f"{key}: {data[key]}")

    elif isinstance(data, list):
        if data and all(isinstance(item, dict) for item in data):
            sorted_items = sorted(
                data,
                key=lambda item: (
                    item.get("severity") or "",
                    item.get("rule") or "",
                    item.get("src_ip") or "",
                )
            )
        else:
            sorted_items = data

        for i, item in enumerate(sorted_items, start=1):
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

def build_detection_summary(detections: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    severity_counter = Counter()
    rule_counter = Counter()
    total_findings = 0

    for findings in detections.values():
        total_findings += len(findings)
        for finding in findings:
            severity_counter[finding.get("severity") or "unknown"] += 1
            rule_counter[finding.get("rule") or "unknown_rule"] += 1
    return {
        "total_findings": total_findings,
        "by_severity": dict(severity_counter),
        "by_rule": dict(rule_counter),
    }
