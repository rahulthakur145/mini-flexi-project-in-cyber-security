import time
import random
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
from config import SAMPLE_PCAP_PATH


def generate_test_pcap(output_path: str = SAMPLE_PCAP_PATH, test_gmail: str = "admin.symbiosis@gmail.com") -> dict:
    packets = []
    base_time = time.time() - 60.0
    curr_time = base_time

    def add_pkt(pkt, dt=0.05):
        nonlocal curr_time
        curr_time += dt
        pkt.time = curr_time
        packets.append(pkt)

    # 1. Benign Traffic (50 packets)
    for _ in range(50):
        sport = random.randint(49152, 65000)
        dport = random.choice([80, 443, 53])
        if dport == 53:
            pkt = Ether() / IP(src="10.0.2.10", dst="10.0.2.15") / UDP(sport=sport, dport=53) / Raw(load="X" * 64)
        else:
            pkt = Ether() / IP(src="10.0.2.10", dst="10.0.2.15") / TCP(sport=sport, dport=dport, flags="PA") / Raw(load="GET /index.html HTTP/1.1\r\n" * 8)
        add_pkt(pkt, dt=0.1)

    # 2. Port Scan Scenario (15 distinct destination ports from 192.168.56.101)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
    for port in scan_ports:
        pkt = Ether() / IP(src="192.168.56.101", dst="10.0.2.15") / TCP(sport=54321, dport=port, flags="S")
        add_pkt(pkt, dt=0.08)

    # 3. Repeated SSH Brute-Force Attempts (12 rapid attempts to Port 22 from 192.168.56.102)
    for i in range(12):
        pkt = Ether() / IP(src="192.168.56.102", dst="10.0.2.15") / TCP(sport=40000 + i, dport=22, flags="S") / Raw(load="SSH-2.0-OpenSSH")
        add_pkt(pkt, dt=0.12)

    # 4. TCP SYN Flood Burst (30 rapid SYN packets from 192.168.56.103)
    for i in range(30):
        pkt = Ether() / IP(src="192.168.56.103", dst="10.0.2.15") / TCP(sport=30000 + i, dport=80, flags="S")
        add_pkt(pkt, dt=0.02)

    # 5. TCP Xmas Scan & ML Anomaly Packet (from 192.168.56.104)
    xmas_pkt = Ether() / IP(src="192.168.56.104", dst="10.0.2.15") / TCP(sport=1234, dport=9999, flags="FPU") / Raw(load="A" * 1450)
    add_pkt(xmas_pkt, dt=0.1)

    # 6. Suspicious Credential / Gmail ID Payload Leak (from 192.168.56.105 on SMTP Port 25)
    if test_gmail:
        clean_gmail = test_gmail.split(",")[0].strip()
        email_payload = f"AUTH LOGIN user={clean_gmail} pass=Secret12345\r\n"
        gmail_pkt = Ether() / IP(src="192.168.56.105", dst="10.0.2.15") / TCP(sport=51515, dport=25, flags="PA") / Raw(load=email_payload)
        add_pkt(gmail_pkt, dt=0.1)

    # 7. Simulated Gmail Brute-Force / Hacking Attempt (8 rapid connection attempts to Port 993 IMAPS from 192.168.56.106)
    for i in range(8):
        pkt = Ether() / IP(src="192.168.56.106", dst="10.0.2.15") / TCP(sport=50000 + i, dport=993, flags="S") / Raw(load=f"IMAP-LOGIN user={test_gmail} pass=wrongpass{i}")
        add_pkt(pkt, dt=0.08)

    wrpcap(output_path, packets)
    return {
        "pcap_path": output_path,
        "total_packets": len(packets)
    }