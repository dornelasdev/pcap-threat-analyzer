# PCAP Threat Analyzer

A Python-based PCAP threat analyzer.
*Currently being built for learning purposes.*

## Description

Its main goal is to read PCAP files, extract network/packet information, and later expand into traffic analysis and simple threat detection.
*Current focus is foundation first, not yet focused on full detection.*

## Current Features (v0.2)
- Reads a PCAP file.
- Parses through packets.
- Extracts basic network fields.
- Normalizes packet records for future detection/statistics modules.
- Computes basic stats (protocol counts, top source IPs, top destination ports).
- Sectioned CLI output.

## Project Structure
- `main.py`: current entry point for the project.
  - `parse_pcap()`: reads a PCAP file and converts its packets into a simpler internal structure.
  - `compute_basic_stats()`: handles data aggregation.
  - `print_section()`: delivers readable output.

## Roadmap
- **v0.3**: simple suspicious behavior detection.
- **v0.4**: improved reporting and output modes.
- **v0.5**: modular refactor into separate files.
- **v0.55**: optional threat-intel enrichment.

