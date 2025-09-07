# core/packet_scanner.py (with friendly names on Windows)

import tempfile
import os
import platform
from scapy.all import sniff, wrpcap, get_if_list

def list_interfaces():
    """Return a list of available network interfaces with friendly names if possible."""
    try:
        interfaces = get_if_list()
        if platform.system() == "Windows":
            try:
                import psutil
                nic_info = psutil.net_if_addrs().keys()
                # Map friendly names if psutil gives more readable labels
                friendly = []
                for name in nic_info:
                    friendly.append(name)
                if friendly:
                    return list(friendly)
            except Exception as e:
                print(f"[!] Failed to map Windows friendly names: {e}")
        return interfaces
    except Exception as e:
        print(f"[!] Failed to list interfaces: {e}")
        return []

def scan_network(interface=None, protocol=None, duration=5):
    """
    Captures network packets and writes them to a temporary .pcap file.
    Supports filtering by a single protocol (string).
    Always returns an absolute path to the file or None if failed.
    """
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        tmp_path = tmp.name
        tmp.close()

        # Build BPF filter string
        bpf_filter = None
        if protocol and protocol.upper() != "ALL":
            bpf_filter = protocol.lower()

        print(f"[*] Starting sniff on {interface} for {duration}s with filter: {bpf_filter}")
        packets = sniff(iface=interface, timeout=duration, filter=bpf_filter)
        wrpcap(tmp_path, packets)
        print(f"[*] Capture saved to {tmp_path} ({len(packets)} packets)")
        return tmp_path
    except Exception as e:
        print(f"[!] scan_network failed: {e}")
        return None
