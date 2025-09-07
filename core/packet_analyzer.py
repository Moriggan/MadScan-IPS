# core/packet_analyzer.py

import os
import binascii
from scapy.all import rdpcap, Packet
from datetime import datetime

def hex_dump(raw_bytes, length=16):
    """Format bytes into a hex dump string."""
    if not raw_bytes:
        return ""
    lines = []
    for i in range(0, len(raw_bytes), length):
        chunk = raw_bytes[i:i+length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)

def format_packet(pkt: Packet, index: int) -> dict:
    """Extract structured info for a packet."""
    info = {
        "Index": index,
        "Summary": pkt.summary(),
        "Time": getattr(pkt, "time", None),
        "Layers": {},
        "HexDump": "",
    }

    try:
        if pkt.haslayer("Ether"):
            ether = pkt.getlayer("Ether")
            info["Layers"]["Ethernet"] = {
                "src": ether.src,
                "dst": ether.dst,
                "type": ether.type
            }

        if pkt.haslayer("IP"):
            ip = pkt.getlayer("IP")
            info["Layers"]["IP"] = {
                "src": ip.src,
                "dst": ip.dst,
                "ttl": ip.ttl,
                "proto": ip.proto,
                "len": ip.len
            }

        if pkt.haslayer("TCP"):
            tcp = pkt.getlayer("TCP")
            info["Layers"]["TCP"] = {
                "sport": tcp.sport,
                "dport": tcp.dport,
                "flags": str(tcp.flags),
                "seq": tcp.seq,
                "ack": tcp.ack
            }

        if pkt.haslayer("UDP"):
            udp = pkt.getlayer("UDP")
            info["Layers"]["UDP"] = {
                "sport": udp.sport,
                "dport": udp.dport,
                "len": udp.len
            }

        if pkt.haslayer("ICMP"):
            icmp = pkt.getlayer("ICMP")
            info["Layers"]["ICMP"] = {
                "type": icmp.type,
                "code": icmp.code
            }

        # Payload
        if hasattr(pkt, "load"):
            raw = bytes(pkt.load)
            info["Layers"]["Payload"] = {
                "length": len(raw),
                "preview": raw[:32].hex() + ("..." if len(raw) > 32 else "")
            }
            info["HexDump"] = hex_dump(raw)

        # Format time
        if info["Time"]:
            info["Time"] = datetime.fromtimestamp(info["Time"]).strftime("%H:%M:%S.%f")[:-3]

    except Exception as e:
        info["Layers"]["Error"] = str(e)

    return info

def analyze_packets(capture_file):
    """Read packets from a PCAP and return structured data."""
    if not capture_file or not os.path.exists(capture_file):
        return []

    try:
        packets = rdpcap(capture_file)
        results = [format_packet(pkt, i) for i, pkt in enumerate(packets)]
        return results
    except Exception as e:
        print(f"[!] analyze_packets failed: {e}")
        return []
