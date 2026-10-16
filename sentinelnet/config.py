import os

# Database & File Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sentinelnet_events.db")
SAMPLE_PCAP_PATH = os.path.join(BASE_DIR, "sample_traffic.pcap")

# Detection Rule Thresholds (Sliding Window in Seconds)
TIME_WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 10         # Unique destination ports within window
SYN_FLOOD_THRESHOLD = 25         # SYN packets to same port within window
TRAFFIC_SPIKE_THRESHOLD = 60     # Total packets from a single IP within window
BRUTE_FORCE_THRESHOLD = 8        # Repeated connections to SSH(22)/RDP(3389)/FTP(21)

# Monitored Sensitive Ports for Brute-Force / Unauthorized Access
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL"
}

# Threat Severity Levels & Scoring
SEVERITY_LEVELS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 95
}

# Automated Threat Response Settings
# Kept in simulation mode by default so you never accidentally lock out your host machine
ENABLE_ACTIVE_FIREWALL_BLOCK = False
WHITELISTED_IPS = {"127.0.0.1", "0.0.0.0", "192.168.1.1"}
# Add these ports to SENSITIVE_PORTS in config.py
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    465: "SMTPS (Gmail)",
    587: "SMTP Submission",
    993: "IMAPS (Gmail)",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP"
}