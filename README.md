# Cableshark

A Python network packet sniffer and analyzer that captures and displays traffic for TCP, UDP, and ICMP protocols. Similar in concept to tcpdump or Wireshark, but implemented as a lightweight command-line tool with zero external dependencies.

## Features

- Real-time packet capture from network interfaces
- Protocol header parsing for Ethernet, IPv4, TCP, UDP, and ICMP
- Flexible filtering by protocol, source/destination IP, and source/destination port
- DNS reverse lookups with caching for hostname resolution
- Cross-platform support (Linux and Windows)

## Prerequisites

- Python 3.6+
- **Elevated privileges** are required for raw socket access:
  - **Linux**: Run with `sudo`
  - **Windows**: Run as Administrator

## Usage

```
python main.py [-protocol <TCP|UDP|ICMP>] [-src <IP>] [-dest <IP>]
               [-srcport <1-65535>] [-destport <1-65535>]
```

### Options

| Flag | Description |
|------|-------------|
| `-protocol` | Filter by protocol: `TCP`, `UDP`, or `ICMP` |
| `-src` | Filter by source IP address |
| `-dest` | Filter by destination IP address |
| `-srcport` | Filter by source port (not valid for ICMP) |
| `-destport` | Filter by destination port (not valid for ICMP) |
| `--help` | Show usage information |

### Examples

Capture all traffic (no filters):
```bash
sudo python main.py
```

Capture only TCP traffic:
```bash
sudo python main.py -protocol TCP
```

Capture UDP traffic to a specific destination:
```bash
sudo python main.py -protocol UDP -dest 192.168.1.1
```

Capture TCP traffic from a specific source on port 80:
```bash
sudo python main.py -protocol TCP -src 10.0.0.1 -destport 80
```

## Architecture

The project consists of two modules:

- **`main.py`** - CLI argument parsing, input validation, packet filtering, display logic, and the main capture loop.
- **`unpack.py`** - Binary packet header unpacking for Ethernet, IPv4, TCP, UDP, and ICMP using Python's `struct` module.

### Packet Processing Flow

1. Parse and validate CLI filter arguments
2. Open a raw socket on the selected network interface
3. Capture packets in an infinite loop
4. Unpack Ethernet, IP, and protocol-specific headers
5. Apply user-specified filters
6. Display matching packets with full header breakdown and payload

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / help displayed |
| 1 | Keyword-value count mismatch |
| 2 | Invalid keyword |
| 3 | Unsupported protocol |
| 4 | Invalid destination IP |
| 5 | Invalid destination port |
| 6 | Invalid source IP |
| 7 | Invalid source port |

## Running Tests

```bash
pip install pytest
pytest
```
