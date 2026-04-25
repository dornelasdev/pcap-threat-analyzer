# PCAP Threat Analyzer

A Python-based PCAP threat analyzer.
*Built for learning purposes.*

## Description

Its main goal is to read PCAP files, extract network/packet information, and later expand into traffic analysis and simple threat detection.
*Current focus is foundation first, not yet focused on full detection.*

## Current Features (v1.0)
- PCAP parsing: reads packets and normalizes core fields.
- Traffic statistics: protocol counts, top source IPs, top destination ports.
- Threat detection: port scan, high connection volume, DNS query volume patterns.
- Output modes: readable text report and file export via -f/--output-file (json or text).
- DNS-aware analysis: extracts DNS query fields and adds DNS-focused statistics.
- Runtime metrics for both parsing and pipeline workflows.
- Improved input and error handling for invalid thresholds, file usage, and cleaner parser errors.
- PoC validation: includes controlled port-scan and DNS-query scenarios with Wireshark evidence and analyzer outputs.

## Project Structure
- `main.py`: current entry point for the project.
  - `parse_pcap()`: reads a PCAP file and converts its packets into a simpler internal structure.
  - `compute_basic_stats()`: handles data aggregation.
  - `main()`: orchestrates parsing, stats, detection and output.
- `helpers/detection_rules.py`: contains threat-detection patterns.
  - `detect_threats()`: returns structured findings by detection type.
- `helpers/reporting.py`: handles output formatting.
  - `build_report()`: assembles parsed packets, stats, and detections into one report object.
  - `render_text_report()`: prints the report in terminal format with sections.
  - `render_json()`: serializes the report object to JSON output.
  - `print_section()`: formats section output and detection findings for readability.
  - `build_detection_summary()`: summary for report findings.
  - `render_text_report_impl()`: internal renderer used by text output paths.
