
### `Made By Moriggan With Help Venice AI`

```python
import argparse
from core.packet_scanner import scan_network
from core.packet_analyzer import analyze_packets
from core.auto_prevention import prevent_dos_ddos

def main():
    parser = argparse.ArgumentParser(description='PacketCatcher CLI')
    parser.add_argument('--interface', type=str, required=True, help='Network interface to scan')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'icmp', 'http'], help='Protocol to scan')
    parser.add_argument('--malicious', action='store_true', help='Enable malicious packet detection')

    args = parser.parse_args()

    print(f"Scanning interface: {args.interface}")
    print(f"Protocol: {args.protocol}")
    print(f"Malicious packet detection: {'Enabled' if args.malicious else 'Disabled'}")

    # Scan the network
    capture_file = scan_network(args.interface, args.protocol)

    # Analyze packets
    if args.malicious:
        malicious_packets = analyze_packets(capture_file)
        print(f"Malicious packets detected: {malicious_packets}")
    else:
        print("Malicious packet detection disabled.")

    # Prevent DOS/DDOS attacks
    prevent_dos_ddos()

if __name__ == '__main__':
    main()