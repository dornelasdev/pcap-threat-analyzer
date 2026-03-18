# PCAP Threat Analyzer

A Python-based PCAP threat analyzer.
*Currently being built for learning purposes.*

## Description

Its main goal is to read PCAP files, extract network/packet information, and later expand into traffic analysis and simple threat detection.
*Current focus is foundation first, not yet focused on full detection.*

## Current Features (v0.5)
- PCAP parsing: reads packets and normalizes core fields.
- Traffic statistics: protocol counts, top source IPs, top destination ports.
- Threat detection: port scan, high connection volume, DNS query volume patterns.
- Output modes: readable text report and JSON file export (`-o json`, optional `-f/--output-file`).

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

## Roadmap
- **v0.6**: DNS-aware parsing and detection improvements.
- **v0.7**: improved reporting and output modes (better summary + detailed findings).
- **v0.8**: validation and quality pass (cleaner CLI UX, threshold tuning, test PCAP set).


