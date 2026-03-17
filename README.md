# PCAP Threat Analyzer

A Python-based PCAP threat analyzer.
*Currently being built for learning purposes.*

## Description

Its main goal is to read PCAP files, extract network/packet information, and later expand into traffic analysis and simple threat detection.
*Current focus is foundation first, not yet focused on full detection.*

## Current Features (v0.3)
- Reads a PCAP file.
- Parses through packets.
- Extracts basic network fields.
- Normalizes packet records for future detection/statistics modules.
- Computes basic stats (protocol counts, top source IPs, top destination ports).
- Sectioned CLI output.
- Detection rules for port scanning, high connection volume, and DNS queries.

## Project Structure
- `main.py`: current entry point for the project.
  - `parse_pcap()`: reads a PCAP file and converts its packets into a simpler internal structure.
  - `compute_basic_stats()`: handles data aggregation.
  - `print_section()`: delivers readable output.
  - `main()`: orchestrates parsing, stats, detection and output.
- `detection_rules.py`: contains threat-detection patterns.
  - `detect_threats()`: returns structured findings by detection type.

## Roadmap
- **v0.4**: improved reporting and output modes.
- **v0.5**: modular refactor into separate files.

