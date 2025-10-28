# TLS-SNI-Monitor
🔍 Lightweight TLS ClientHello SNI Sniffer and Traffic Auditor.  A Python tool utilizing Scapy to extract the Server Name Indication (SNI) from TLS ClientHello packets on port 443. Designed for local network monitoring, with a special focus on identifying and filtering Discord connections for diagnostic or educational purposes.



# 1. Required Python Libraries

Librarian (Scapy, Rich) required via `pip`:

`bash
pip install scapy rich`



# 2. Startup Options

Monitoring ONLY Discord Traffic
`sudo python sniffer.py --iface "Wi-Fi" --only-discord`

Monitorowanie CAŁEGO Ruchu TLS
`sudo python sniffer.py --iface "Wi-Fi" --all-tls`
