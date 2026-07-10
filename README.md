# PacketSniffer

A raw-socket packet sniffer for Linux, written from scratch in C++ to understand how packets actually look on the wire — parsing Ethernet, IPv4, TCP, UDP, and ICMP headers by hand, with no external packet-parsing libraries (like libpcap).

This is a learning project, not a Wireshark competitor. The goal was to get hands-on with raw sockets, byte-level packet structure, and defensive parsing of untrusted network data, as groundwork for a future IDS/IPS and firewall project.

## Features

- Captures raw packets directly off a network interface using `AF_PACKET` raw sockets
- Parses Ethernet, IPv4, TCP, UDP, and ICMP headers
- Bounds-checked at every layer — truncated or malformed packets (e.g. a spoofed `ihl` claiming a header far larger than the actual buffer) are detected and handled instead of read as garbage or crashed on
- Human-readable output: source/dest IPs, ports, protocol, and printable payload data
- Unit test suite (`test_parser`) that hand-builds packets (valid and deliberately malformed) to verify the parser's behavior without needing root or a live network interface

## Requirements

- Linux (uses `AF_PACKET` raw sockets, not portable to macOS/Windows)
- CMake 3.16+
- A C++17 compiler (g++ or clang++)
- Root privileges, or the `CAP_NET_RAW` capability, to open a raw socket

## Building

```bash
git clone <this-repo-url>
cd PacketSniffer
mkdir build && cd build
cmake ..
make
```

This produces two binaries: `sniffer` and `test_parser`.

## Running

The sniffer needs raw socket access, so run it with `sudo` or grant the capability directly:

```bash
sudo ./sniffer
```

or, to avoid running the whole thing as root:

```bash
sudo setcap cap_net_raw+ep ./sniffer
./sniffer
```

You'll be prompted for a network interface (e.g. `eth0`, `wlan0`, `enp3s0` — check `ip a` if you're not sure). The sniffer will then print each captured packet's headers and payload until you stop it with Ctrl+C.

### Example output

```
Destination IP: 192.168.1.20
Source IP: 192.168.1.10
Protcol: TCP
Source Port: 443
Destination Port: 51000
Data:
GET / HTTP/1.1**Host: example.com****
Successfully snagged packet #1 (74 bytes)
```

## Testing

```bash
cd build
./test_parser
```

The test suite builds packets byte-by-byte in memory (no network needed) to cover:
- A buffer too small to contain even an Ethernet header
- A buffer big enough for Ethernet but too small for a full IP header
- A fully well-formed IPv4 + TCP packet (the "happy path")
- An IP header with a spoofed `ihl` claiming a 60-byte header when the buffer doesn't have one, to make sure the parser doesn't read out of bounds

## Architecture

```
Raw           – opens the AF_PACKET socket, binds to an interface, captures raw bytes
packet        – thin wrapper around a captured buffer + its length
parser        – reads Ethernet/IP/TCP/UDP/ICMP headers out of a packet, with bounds
                checks at every step so malformed data never causes an out-of-bounds read
data.h        – plain structs for each parsed header (Eth_Header, IP_Header, TCP_Header, ...)
display       – formats a Parsed_Packet for human-readable console output
```

The parser never trusts fields taken from the packet itself (like IP header length) without checking them against the actual captured buffer size first — since in a real capture, every byte is attacker-controlled data.

## Known limitations / roadmap

This currently only understands IPv4 traffic. Deliberately left out for now, as possible future additions:

- IPv6 support
- ARP packet parsing
- VLAN-tagged (802.1Q) frames
- A simple rule/filter engine on top of the parser (the natural next step toward an IDS/firewall)
- Graceful shutdown (currently exits via Ctrl+C without a summary)

## Why I built this

I wanted to understand raw sockets and packet structure at the byte level before building anything higher-level like an intrusion detection system or firewall. This project is that foundation — the parsing and bounds-checking logic here is meant to carry forward into that next project.