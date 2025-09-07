⚡ MadScan
> Advanced Network Packet Scanner & Analyzer with Web Dashboard

## 🚀 Overview
**MadScan** is a modern packet sniffer and scanner with a **real-time web dashboard**, designed for security analysts, network engineers, and curious developers.  
It combines the power of packet capture, firewall management, and live analytics — all in one beautiful interface.  

- 🎛️ **Interactive Web UI** (Flask + Socket.IO)
- 📊 **Real-time charts & stats**
- 🔒 **User authentication & role management**
- 🛡 **Firewall integration (Windows & iptables)**
- 📦 **Export to PCAP, CSV, JSON**
- ⚡ **Suspicious traffic detection & alerts**

---

## ✨ Features
- **Multi-Interface Scanning**: choose your NIC & duration from 5s to 24h
- **Protocol Filters**: TCP, UDP, ICMP, DNS, HTTP, ARP, RDP
- **Admin Panel**: manage users, roles, and system stats
- **Live Connection Monitor**: last X minutes of traffic
- **Configurable Alerts**:
  - Large packets (100MB – 1GB thresholds)
  - Flood detection (>100 req/sec per IP)
- **Persistent Scan Settings** (auto-saved & restored)
- **Exports**: CSV, JSON, PCAP (Wireshark compatible)

## 🔧 Installation
```bash
# Clone repo
git clone https://github.com/Moriggan/MadScan-IPS.git
cd MadScan

# Install dependencies
pip install -r requirements.txt

# Run app
python app.py
Then open: http://127.0.0.1:5000

👤 Default Login
Username: admin

Password: admin
```
⚠️ Change the default credentials immediately after first login!

🛡 Security
Passwords stored securely with SHA-256 hashing

Session-based authentication

Role system (Admin / User)

Audit logs planned for future versions

📌 Roadmap
 System tray agent for background sniffing

 Machine learning anomaly detection

 Threat intelligence feed integration


🤝 Contributing
Contributions are welcome!
Open an issue or submit a PR.

📜 License
MIT License © 2025 — MadScan Project
