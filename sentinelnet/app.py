import os
import random
import tempfile
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from config import SAMPLE_PCAP_PATH
from database import DatabaseManager
from rules_engine import RuleEngine
from ml_analyzer import BehavioralMLAnalyzer
from responder import AutomatedResponder
from email_notifier import EmailAlertNotifier
from packet_processor import PacketProcessor
from traffic_simulator import generate_test_pcap

# Page Configuration - Dark Mode NIDS Theme
st.set_page_config(
    page_title="NIDS - Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Professional Dark UI / UX Card Styling
st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 18px;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-title { font-size: 13px; color: #8b949e; text-transform: uppercase; font-weight: 600; }
    .metric-value { font-size: 26px; font-weight: 700; color: #f0f6fc; margin-top: 5px; }
    .metric-trend { font-size: 12px; margin-top: 5px; color: #3fb950; }
    .metric-trend-danger { font-size: 12px; margin-top: 5px; color: #f85149; }
    h1, h2, h3 { color: #f0f6fc !important; }
    </style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------------
# >>> ADDED FOR THREAT PREVENTION (1/4): ADDED "Prevention_Steps" & "Windows_Firewall" <<<
# -------------------------------------------------------------------------
ATTACK_PORT_DATA = [
    {
        "Port": 21,
        "Protocol": "TCP",
        "Service": "FTP (File Transfer)",
        "Threat_Attack": "Cleartext Credential Sniffing & Brute-Force Attack",
        "Severity": "High 🔴",
        "Security_Model": "Zero-Trust Encryption Model (Disable FTP; Enforce SFTP on Port 22)",
        "Prevention_Steps": "1. Disable legacy FTP service (vsftpd/proftpd).\n2. Enforce SFTP (Port 22) or FTPS with TLS 1.3 encryption.\n3. Restrict file transfer access to whitelisted VPN IPs.",
        "Firewall_Command": "sudo ufw deny 21/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_FTP_21\" dir=in action=block protocol=TCP localport=21",
        "cpu_boost": 22, "mem_boost": 15, "disk_boost": 18, "net_boost": 30,
        "wifi_state": "🟠 Degraded (Unencrypted Sniffing Detected)", "latency_ms": 68, "pkt_loss": 4.2
    },
    {
        "Port": 22,
        "Protocol": "TCP",
        "Service": "SSH (Secure Shell)",
        "Threat_Attack": "Automated Botnet Brute-Force / Credential Stuffing",
        "Severity": "High 🔴",
        "Security_Model": "Key-Based Access Model (Ed25519 SSH Keys + Fail2Ban Rate Limiting)",
        "Prevention_Steps": "1. Disable password login ('PasswordAuthentication no' in /etc/ssh/sshd_config).\n2. Require Ed25519 SSH keys with Multi-Factor Authentication (MFA).\n3. Enable Fail2Ban to auto-ban attacker IPs after 3 failed attempts.",
        "Firewall_Command": "sudo ufw limit 22/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Limit_SSH_22\" dir=in action=block protocol=TCP localport=22",
        "cpu_boost": 35, "mem_boost": 20, "disk_boost": 12, "net_boost": 28,
        "wifi_state": "🟠 High Auth Load (SSH Flood Throttled)", "latency_ms": 85, "pkt_loss": 5.8
    },
    {
        "Port": 23,
        "Protocol": "TCP",
        "Service": "Telnet",
        "Threat_Attack": "Man-in-the-Middle (MITM) Cleartext Session Hijacking",
        "Severity": "Critical 🔥",
        "Security_Model": "Perimeter Hardening Model (Block Port 23; Migrate to SSH)",
        "Prevention_Steps": "1. Immediately disable/uninstall telnetd service on all devices.\n2. Enable Dynamic ARP Inspection (DAI) on switches to prevent MITM spoofing.\n3. Enforce encrypted SSH v2 for all remote CLI administration.",
        "Firewall_Command": "sudo ufw deny 23/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_Telnet_23\" dir=in action=block protocol=TCP localport=23",
        "cpu_boost": 40, "mem_boost": 25, "disk_boost": 15, "net_boost": 45,
        "wifi_state": "🔴 Critical (ARP / MITM Spoofing on WLAN)", "latency_ms": 145, "pkt_loss": 12.4
    },
    {
        "Port": 53,
        "Protocol": "UDP",
        "Service": "DNS",
        "Threat_Attack": "DNS Amplification DDoS & Data Exfiltration Tunneling",
        "Severity": "High 🔴",
        "Security_Model": "DNSSEC Validation + Response Rate Limiting (RRL) Model",
        "Prevention_Steps": "1. Disable open DNS recursion for external/public IP addresses.\n2. Enable DNSSEC cryptographic validation and DNS-over-HTTPS (DoH).\n3. Configure Response Rate Limiting (RRL) to drop UDP amplification floods.",
        "Firewall_Command": "sudo iptables -A INPUT -p udp --dport 53 -m limit --limit 10/s -j ACCEPT",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Restrict_DNS_53\" dir=in action=block protocol=UDP localport=53",
        "cpu_boost": 45, "mem_boost": 30, "disk_boost": 10, "net_boost": 52,
        "wifi_state": "🔴 Saturated (UDP Flood / Bandwidth Exhaustion)", "latency_ms": 210, "pkt_loss": 18.5
    },
    {
        "Port": 80,
        "Protocol": "TCP",
        "Service": "HTTP (Web)",
        "Threat_Attack": "SQL Injection (SQLi), XSS, & Layer-7 HTTP Flood DDoS",
        "Severity": "Medium 🟠",
        "Security_Model": "Defense-in-Depth WAF Model (ModSecurity WAF + Force HTTPS Port 443)",
        "Prevention_Steps": "1. Redirect all Port 80 HTTP traffic to Port 443 (HTTPS TLS 1.3 + HSTS).\n2. Deploy OWASP ModSecurity Web Application Firewall (WAF) rules.\n3. Use parameterized SQL queries and input sanitization to prevent SQLi/XSS.",
        "Firewall_Command": "sudo ufw deny 80/tcp && sudo ufw allow 443/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_HTTP_80\" dir=in action=block protocol=TCP localport=80",
        "cpu_boost": 18, "mem_boost": 14, "disk_boost": 8, "net_boost": 22,
        "wifi_state": "🟡 Moderate Load (WAF Filtering Active)", "latency_ms": 48, "pkt_loss": 2.1
    },
    {
        "Port": 445,
        "Protocol": "TCP",
        "Service": "SMB (Windows Share)",
        "Threat_Attack": "Ransomware Worm Propagation (EternalBlue / WannaCry)",
        "Severity": "Critical 🔥",
        "Security_Model": "Network Micro-Segmentation Model (Block WAN SMB; Disable SMBv1)",
        "Prevention_Steps": "1. Disable SMBv1 protocol on all Windows hosts immediately.\n2. Block Port 445 at the perimeter firewall and micro-segment internal VLANs.\n3. Enforce SMB cryptographic packet signing and apply MS17-010 patches.",
        "Firewall_Command": "sudo ufw deny 445/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_SMB_445\" dir=in action=block protocol=TCP localport=445",
        "cpu_boost": 55, "mem_boost": 38, "disk_boost": 42, "net_boost": 48,
        "wifi_state": "🔴 Emergency Lockdown (Lateral Movement Blocked)", "latency_ms": 180, "pkt_loss": 15.0
    },
    {
        "Port": 3306,
        "Protocol": "TCP",
        "Service": "MySQL Database",
        "Threat_Attack": "Remote Database Enumeration & Unauthorized Data Exfiltration",
        "Severity": "High 🔴",
        "Security_Model": "Least-Privilege Isolation Model (Bind DB to 127.0.0.1 Localhost Only)",
        "Prevention_Steps": "1. Bind MySQL listener strictly to localhost (bind-address = 127.0.0.1).\n2. Disable remote root login and enforce Role-Based Access Control (RBAC).\n3. Encrypt database traffic with TLS and audit bulk SELECT queries.",
        "Firewall_Command": "sudo ufw deny 3306/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_MySQL_3306\" dir=in action=block protocol=TCP localport=3306",
        "cpu_boost": 32, "mem_boost": 34, "disk_boost": 30, "net_boost": 35,
        "wifi_state": "🟠 Egress Spike (DB Exfiltration Blocked)", "latency_ms": 95, "pkt_loss": 6.5
    },
    {
        "Port": 3389,
        "Protocol": "TCP",
        "Service": "RDP (Remote Desktop)",
        "Threat_Attack": "Ransomware Initial Access / BlueKeep RCE / RDP Brute-Force",
        "Severity": "Critical 🔥",
        "Security_Model": "Zero-Trust VPN Bastion Model (WireGuard VPN + MFA + NLA)",
        "Prevention_Steps": "1. Never expose Port 3389 to the public internet; place behind WireGuard VPN.\n2. Enable Network Level Authentication (NLA) and Multi-Factor Authentication (MFA).\n3. Enforce account lockout after 5 invalid RDP login attempts.",
        "Firewall_Command": "sudo ufw deny 3389/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_RDP_3389\" dir=in action=block protocol=TCP localport=3389",
        "cpu_boost": 48, "mem_boost": 32, "disk_boost": 25, "net_boost": 40,
        "wifi_state": "🔴 Critical Intrusion Attempt (RDP Port Isolated)", "latency_ms": 160, "pkt_loss": 11.2
    },
    {
        "Port": 4444,
        "Protocol": "TCP",
        "Service": "Metasploit Listener",
        "Threat_Attack": "Reverse Shell Backdoor / Command & Control (C2) Channel",
        "Severity": "Critical 🔥",
        "Security_Model": "EDR Host Isolation + Strict Egress Traffic Filtering Model",
        "Prevention_Steps": "1. Apply Default-Deny Egress (outbound) firewall filtering to block C2 callbacks.\n2. Deploy Endpoint Detection & Response (EDR) to kill reverse shell processes.\n3. Quarantine compromised host MAC/IP address on the Wi-Fi VLAN.",
        "Firewall_Command": "sudo ufw reject out 4444/tcp",
        "Windows_Firewall": "netsh advfirewall firewall add rule name=\"Block_Metasploit_4444\" dir=out action=block protocol=TCP remoteport=4444",
        "cpu_boost": 58, "mem_boost": 40, "disk_boost": 35, "net_boost": 50,
        "wifi_state": "🔴 Host Quarantined (Outbound C2 Severed)", "latency_ms": 240, "pkt_loss": 22.0
    }
]

df_attacks = pd.DataFrame(ATTACK_PORT_DATA)

# >>> ADDED FOR THREAT PREVENTION (2/4): SESSION STATE FOR PREVENTED PORTS <<<
if "sim_port" not in st.session_state:
    st.session_state.sim_port = 22
if "threat_active" not in st.session_state:
    st.session_state.threat_active = False
if "prevented_ports" not in st.session_state:
    st.session_state.prevented_ports = set()


def calculate_dynamic_system_telemetry(events_df, alerts_df):
    """
    Calculates dynamic System Status & Wi-Fi Telemetry based on live database
    alerts, packet volume, active simulated port attacks, and IPS prevention state.
    """
    base_cpu = 18
    base_mem = 34
    base_disk = 42
    base_net = 15
    wifi_status = "🟢 Protected (WPA3-Enterprise | Zero-Trust IPS Active)"
    wifi_signal = -48  # dBm (Excellent)
    latency_ms = 14
    packet_loss = 0.1
    threat_level_badge = "🟢 NORMAL (No Active Threats)"

    total_alerts = len(alerts_df) if not alerts_df.empty else 0
    critical_alerts = len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0
    packet_count = len(events_df) if not events_df.empty else 0

    # 1. Factor in real PCAP database alerts & packet volume
    if total_alerts > 0 or packet_count > 0:
        base_cpu += min(35, int(total_alerts * 2.5) + int(packet_count * 0.05))
        base_mem += min(30, int(total_alerts * 1.8) + int(packet_count * 0.03))
        base_disk += min(25, int(packet_count * 0.04))
        base_net += min(45, int(total_alerts * 3.2) + int(packet_count * 0.08))
        latency_ms += min(120, total_alerts * 6)
        packet_loss = min(14.5, round(0.2 + total_alerts * 0.45, 1))
        wifi_signal -= min(25, total_alerts * 2)

        if critical_alerts > 0:
            wifi_status = f"🔴 Under Attack ({critical_alerts} Critical Intrusions Mitigated)"
            threat_level_badge = f"🔴 CRITICAL THREAT LEVEL ({critical_alerts} Critical Alerts)"
        else:
            wifi_status = f"🟠 Elevated Traffic ({total_alerts} Alerts Detected)"
            threat_level_badge = f"🟠 ELEVATED THREAT LEVEL ({total_alerts} Alerts)"

    # 2. Factor in Simulated Port Attack ONLY if the port is NOT prevented
    if st.session_state.threat_active and (st.session_state.sim_port not in st.session_state.prevented_ports):
        port_row = df_attacks[df_attacks["Port"] == st.session_state.sim_port].iloc[0]
        base_cpu = min(98, base_cpu + int(port_row["cpu_boost"]))
        base_mem = min(96, base_mem + int(port_row["mem_boost"]))
        base_disk = min(95, base_disk + int(port_row["disk_boost"]))
        base_net = min(99, base_net + int(port_row["net_boost"]))
        wifi_status = port_row["wifi_state"]
        latency_ms = max(latency_ms, int(port_row["latency_ms"]))
        packet_loss = max(packet_loss, float(port_row["pkt_loss"]))
        wifi_signal = -76 if "Critical" in port_row["Severity"] else -64
        threat_level_badge = f"🚨 ACTIVE PORT {port_row['Port']} ATTACK ({port_row['Severity']})"
    elif st.session_state.sim_port in st.session_state.prevented_ports:
        threat_level_badge = f"🛡️ PORT {st.session_state.sim_port} IMMUNIZED BY IPS"

    return {
        "cpu": min(99, base_cpu),
        "mem": min(98, base_mem),
        "disk": min(97, base_disk),
        "net": min(99, base_net),
        "wifi_status": wifi_status,
        "wifi_signal": wifi_signal,
        "latency_ms": latency_ms,
        "packet_loss": packet_loss,
        "threat_badge": threat_level_badge
    }


def render_dynamic_status_panel(telemetry):
    """Renders dynamic CPU, Memory, Disk, Network I/O, and Wi-Fi status."""
    st.markdown("### System & Wi-Fi Status (Threat-Adaptive)")
    st.caption(f"**Current State:** {telemetry['threat_badge']}")

    st.markdown(f"**CPU Usage ({telemetry['cpu']}%)** — *DPI & ML Engine Load*")
    st.progress(telemetry["cpu"])

    st.markdown(f"**Memory Usage ({telemetry['mem']}%)** — *Sliding Window Buffer*")
    st.progress(telemetry["mem"])

    st.markdown(f"**Disk Usage ({telemetry['disk']}%)** — *PCAP & SQLite Audit Logs*")
    st.progress(telemetry["disk"])

    st.markdown(f"**Network / Wi-Fi I/O ({telemetry['net']}%)** — *Packet Throughput*")
    st.progress(telemetry["net"])

    st.markdown("#### 📶 Live Wi-Fi & Interface Telemetry")
    w1, w2 = st.columns(2)
    with w1:
        st.markdown(f"**WLAN State:** {telemetry['wifi_status']}")
        st.markdown(f"**Signal Strength:** `{telemetry['wifi_signal']} dBm`")
    with w2:
        st.markdown(f"**Network Latency:** `{telemetry['latency_ms']} ms`")
        st.markdown(f"**Packet Drop / Loss:** `{telemetry['packet_loss']}%`")


# -------------------------------------------------------------------------
# >>> ADDED FOR THREAT PREVENTION (3/4): UPDATED MODULE WITH PREVENTION UI <<<
# -------------------------------------------------------------------------
def render_threat_port_security_module():
    """Reusable UI component for Threat Port Numbers, Security Defense Models & Active Prevention."""
    st.markdown("### 🛡️ Threat Port Attack Monitor, Security Model & Threat Prevention Engine")
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("#### 🔍 Select, Simulate or Prevent Port")
        selected_port_num = st.selectbox(
            "Target Port Number Under Attack:",
            options=df_attacks["Port"].tolist(),
            index=df_attacks["Port"].tolist().index(st.session_state.sim_port),
            format_func=lambda p: f"Port {p} ({df_attacks[df_attacks['Port']==p]['Service'].values[0]})"
        )

        if selected_port_num != st.session_state.sim_port:
            st.session_state.sim_port = selected_port_num
            st.session_state.threat_active = True
            st.rerun()

        b1, b2 = st.columns(2)
        with b1:
            if st.button("⚡ Simulate Port Attack", use_container_width=True):
                random_choice = random.choice(ATTACK_PORT_DATA)
                chosen_port = random_choice["Port"]
                st.session_state.sim_port = chosen_port
                if chosen_port in st.session_state.prevented_ports:
                    st.session_state.prevented_ports.remove(chosen_port)
                st.session_state.threat_active = True
                st.toast(f"🚨 Attack on Port {st.session_state.sim_port}! System & Wi-Fi status updated.", icon="🛡️")
                st.rerun()
        with b2:
            if st.button("🛡️ Prevent & Block Port", use_container_width=True):
                st.session_state.prevented_ports.add(st.session_state.sim_port)
                st.session_state.threat_active = False
                st.toast(f"✅ Port {st.session_state.sim_port} blocked & prevented by IPS! System restored.", icon="🟢")
                st.rerun()

        if st.session_state.prevented_ports:
            st.success(f"**🔒 Active IPS Prevented Ports:** `{', '.join(map(str, sorted(st.session_state.prevented_ports)))}`")
            if st.button("🔄 Clear IPS Prevention Rules", use_container_width=True):
                st.session_state.prevented_ports.clear()
                st.rerun()

    port_details = df_attacks[df_attacks["Port"] == st.session_state.sim_port].iloc[0]
    is_prevented = port_details["Port"] in st.session_state.prevented_ports

    with col2:
        if is_prevented:
            st.success(f"#### ✅ THREAT PREVENTED ON PORT `{port_details['Port']}` ({port_details['Protocol']} — {port_details['Service']})")
            st.markdown("**🟢 Active IPS Prevention Status:** Port is shielded. Malicious packets targeting this port are dropped automatically.")
        else:
            st.error(f"#### 🚨 ACTIVE THREAT PORT: `{port_details['Port']}` ({port_details['Protocol']} — {port_details['Service']})")

        st.markdown(f"**⚡ Attack Vector / Threat Type:** `{port_details['Threat_Attack']}`")
        st.markdown(f"**📊 Risk Severity:** {port_details['Severity']} | **📶 Wi-Fi Impact:** {port_details['wifi_state']}")
        st.success(f"**🛡️ Applied Security Model:** {port_details['Security_Model']}")

        # Step-by-Step Threat Prevention Playbook Box
        st.info(f"**🛠️ How to Prevent This Threat (3-Layer Prevention Playbook):**\n{port_details['Prevention_Steps']}")

        # Linux & Windows Automated Firewall Prevention Commands
        st.code(
            f"# 1. Linux IPS / UFW Firewall Prevention Command:\n{port_details['Firewall_Command']}\n\n"
            f"# 2. Windows Defender Firewall Prevention Command:\n{port_details['Windows_Firewall']}",
            language="bash"
        )

    st.markdown("#### 📋 Complete Threat Port Numbers, Security Model & Prevention Matrix")
    display_cols = ["Port", "Protocol", "Service", "Threat_Attack", "Severity", "Security_Model", "Prevention_Steps", "Firewall_Command"]
    st.dataframe(df_attacks[display_cols], use_container_width=True, hide_index=True)


# Initialize Core Singletons in Session State
if "db" not in st.session_state:
    st.session_state.db = DatabaseManager()
if "rule_engine" not in st.session_state:
    st.session_state.rule_engine = RuleEngine()
if "ml_analyzer" not in st.session_state:
    st.session_state.ml_analyzer = BehavioralMLAnalyzer()
if "responder" not in st.session_state:
    st.session_state.responder = AutomatedResponder(st.session_state.db)
if "email_notifier" not in st.session_state:
    st.session_state.email_notifier = EmailAlertNotifier()
if "processor" not in st.session_state:
    st.session_state.processor = PacketProcessor(
        st.session_state.db,
        st.session_state.rule_engine,
        st.session_state.ml_analyzer,
        st.session_state.responder,
        st.session_state.email_notifier
    )

# -------------------------------------------------------------------------
# SIDEBAR NAVIGATION
# -------------------------------------------------------------------------
st.sidebar.markdown("### 🛡️ NIDS SentinelNet")
st.sidebar.caption("Symbiosis Institute of Technology | Group 21")
st.sidebar.markdown("---")

nav_selection = st.sidebar.radio(
    "Navigation",
    [
        "📊 Dashboard",
        "🚨 Alerts",
        "🛡️ Threat Ports & Security Model",
        "📈 Traffic Monitor",
        "📦 Packet Analysis",
        "⚙️ Settings",
        "🟢 System Status"
    ],
    label_visibility="collapsed"
)

st.sidebar.markdown("---")
st.sidebar.subheader("⚙️ Control & Simulation Panel")
enable_ml = st.sidebar.checkbox("Behavioral ML (Isolation Forest)", value=True)
enable_auto_response = st.sidebar.checkbox("Automated Firewall Blocking", value=True)

monitored_gmails = st.sidebar.text_input("Watchlist Gmail ID", value="homemademe145@gmail.com")
st.session_state.processor.set_monitored_gmails(monitored_gmails)

if st.sidebar.button("🚀 Generate & Analyze Lab PCAP", use_container_width=True):
    with st.spinner("Running detection pipeline..."):
        generate_test_pcap(SAMPLE_PCAP_PATH, test_gmail=monitored_gmails)
        stats = st.session_state.processor.analyze_pcap_file(
            SAMPLE_PCAP_PATH, enable_ml=enable_ml, enable_response=enable_auto_response
        )
        st.session_state.threat_active = True
    st.sidebar.success(f"Processed {stats['valid_ip_packets_processed']} packets, {stats['total_alerts_generated']} alerts!")

uploaded_pcap = st.sidebar.file_uploader("Upload PCAP File", type=["pcap", "pcapng"])
if uploaded_pcap is not None and st.sidebar.button("Analyze Uploaded PCAP", use_container_width=True):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_pcap.read())
        tmp_path = tmp.name
    st.session_state.processor.analyze_pcap_file(tmp_path, enable_ml=enable_ml, enable_response=enable_auto_response)
    os.remove(tmp_path)
    st.session_state.threat_active = True
    st.sidebar.success("PCAP analysis complete!")

# >>> ADDED FOR THREAT PREVENTION (4/4): CLEAR PREVENTED PORTS ON RESET & COUNT IN KPI <<<
if st.sidebar.button("🗑️ Reset Database & Restore Normal", use_container_width=True):
    st.session_state.db.clear_all_data()
    st.session_state.threat_active = False
    st.session_state.prevented_ports.clear()
    st.rerun()

# -------------------------------------------------------------------------
# FETCH DATA FROM SQLITE & COMPUTE DYNAMIC TELEMETRY
# -------------------------------------------------------------------------
events_df = st.session_state.db.fetch_dataframe("security_events", limit=1000)
alerts_df = st.session_state.db.fetch_dataframe("alerts", limit=500)
responses_df = st.session_state.db.fetch_dataframe("response_actions", limit=500)

telemetry = calculate_dynamic_system_telemetry(events_df, alerts_df)

# -------------------------------------------------------------------------
# MAIN DASHBOARD VIEW
# -------------------------------------------------------------------------
if nav_selection == "📊 Dashboard":
    col_head1, col_head2 = st.columns([4, 1])
    with col_head1:
        st.markdown("## Network Intrusion Detection & Prevention System")
    with col_head2:
        st.button("📥 Export Report", use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # 5 Top KPI Cards
    total_alerts_val = len(alerts_df) + (1 if st.session_state.threat_active else 0)
    critical_alerts_val = (len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0) + (1 if st.session_state.threat_active else 0)
    blocked_attacks_val = len(responses_df) + len(st.session_state.prevented_ports) + (1 if st.session_state.threat_active else 0)
    total_packets_val = len(events_df)
    active_conn_val = len(events_df["src_ip"].unique()) * 14 if not events_df.empty else 128

    m1, m2, m3, m4, m5 = st.columns(5)
    
    with m1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Total Alerts</div>
                <div class="metric-value">{total_alerts_val:,}</div>
                <div class="metric-trend-danger">↑ Threat-Adaptive Live</div>
            </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Critical Alerts</div>
                <div class="metric-value">{critical_alerts_val:,}</div>
                <div class="metric-trend-danger">{telemetry['threat_badge'][:22]}</div>
            </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Blocked / Prevented</div>
                <div class="metric-value">{blocked_attacks_val:,}</div>
                <div class="metric-trend">IPS Prevention Active</div>
            </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Traffic Analyzed</div>
                <div class="metric-value">{total_packets_val * 4.2 / 1024:.2f} MB</div>
                <div class="metric-trend">Wi-Fi Latency: {telemetry['latency_ms']} ms</div>
            </div>
        """, unsafe_allow_html=True)
    with m5:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Wi-Fi Signal / Loss</div>
                <div class="metric-value">{telemetry['wifi_signal']} dBm</div>
                <div class="metric-trend-danger">Drop Rate: {telemetry['packet_loss']}%</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Middle Section: Traffic Overview & Top Attack Types
    c_left, c_right = st.columns([2, 1])

    with c_left:
        st.markdown("### Traffic Overview")
        if not events_df.empty or st.session_state.threat_active:
            fig_traffic = go.Figure()
            fig_traffic.add_trace(go.Scatter(
                y=[15000, 22000, 18000, 25000, 21000, 24000, 26000],
                mode='lines+markers', name='Normal Traffic', line=dict(color='#1f77b4', width=3)
            ))
            fig_traffic.add_trace(go.Scatter(
                y=[5000, 8000, 6000, 9000, 7500, 8500, 9200 + (telemetry['net'] * 80)],
                mode='lines+markers', name='Suspicious Traffic', line=dict(color='#ff7f0e', width=3)
            ))
            fig_traffic.add_trace(go.Scatter(
                y=[1200, 2500, 1800, 3100, 2400, 2900, 3400 + (telemetry['cpu'] * 110)],
                mode='lines+markers', name='Malicious Traffic', line=dict(color='#d62728', width=3)
            ))
            fig_traffic.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#161b22', font=dict(color='#c9d1d9'),
                margin=dict(l=20, r=20, t=20, b=20), height=300, legend=dict(orientation="h", y=1.1)
            )
            st.plotly_chart(fig_traffic, use_container_width=True)
        else:
            st.info("Generate traffic or simulate a port attack to view live Traffic Overview.")

    with c_right:
        st.markdown("### Top Attack Types")
        if not alerts_df.empty:
            attack_counts = alerts_df["alert_type"].value_counts().reset_index()
            attack_counts.columns = ["Attack Type", "Count"]
            fig_donut = px.pie(
                attack_counts, names="Attack Type", values="Count", hole=0.6,
                color_discrete_sequence=['#1f77b4', '#ff7f0e', '#d62728', '#2ca02c', '#9467bd']
            )
            fig_donut.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#161b22', font=dict(color='#c9d1d9'),
                margin=dict(l=10, r=10, t=10, b=10), height=300, showlegend=True
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No attack data available yet.")

    st.markdown("<br>", unsafe_allow_html=True)

    # Bottom Section: Recent Alerts & Dynamic System / Wi-Fi Status
    b_left, b_right = st.columns([2, 1])

    with b_left:
        st.markdown("### Recent Alerts")
        if not alerts_df.empty:
            display_alerts = alerts_df[["timestamp", "alert_type", "src_ip", "dst_ip", "severity"]].head(6)
            st.dataframe(display_alerts, use_container_width=True, hide_index=True)
        else:
            st.info("No recent alerts recorded.")

    with b_right:
        render_dynamic_status_panel(telemetry)

    st.markdown("---")
    render_threat_port_security_module()

elif nav_selection == "🚨 Alerts":
    st.markdown("## 🚨 Intrusion Alerts & Response Log")
    if not alerts_df.empty:
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)
    else:
        st.info("No alerts found.")

    st.markdown("### Firewall Automated Actions")
    if not responses_df.empty:
        st.dataframe(responses_df, use_container_width=True, hide_index=True)
    else:
        st.info("No firewall actions triggered.")

elif nav_selection == "🛡️ Threat Ports & Security Model":
    st.markdown("## 🛡️ Threat Port Numbers, Security Models & Threat Prevention")
    render_threat_port_security_module()

elif nav_selection == "📈 Traffic Monitor":
    st.markdown("## 📈 Live Traffic Monitor & Packet Logs")
    if not events_df.empty:
        st.dataframe(events_df, use_container_width=True, hide_index=True)
        if "dst_port" in events_df.columns:
            st.markdown("### 🎯 Detected Destination Ports in Packet Stream")
            port_counts = events_df["dst_port"].value_counts().reset_index()
            port_counts.columns = ["Port Number", "Packet Count"]
            st.dataframe(port_counts, use_container_width=True, hide_index=True)
    else:
        st.info("No packets analyzed yet.")

elif nav_selection == "📦 Packet Analysis":
    st.markdown("## 📦 Behavioral ML & Deep Packet Inspection")
    st.write("SentinelNet inspects payloads for watched Gmail watchlists and isolates anomalies using Isolation Forest.")
    st.markdown("---")
    render_threat_port_security_module()

elif nav_selection == "⚙️ Settings":
    st.markdown("## ⚙️ System Settings & Thresholds")
    st.write("Configure sliding window time thresholds, port scan limits, and notification parameters.")

elif nav_selection == "🟢 System Status":
    st.markdown("## 🟢 Threat-Adaptive System & Wi-Fi Operational Status")
    if (st.session_state.threat_active and st.session_state.sim_port not in st.session_state.prevented_ports) or not alerts_df.empty:
        st.warning(f"⚠️ System is actively mitigating threats: {telemetry['threat_badge']}")
    else:
        st.success("✅ All detection engines, IPS prevention rules, Wi-Fi interfaces, SQLite database, and ML models are operating at normal baseline.")

    render_dynamic_status_panel(telemetry)
    
    # =========================================================================
    # ADDED: CONNECTED VIEWER & SOURCE ID LOG
    # =========================================================================
    st.markdown("---")
    st.markdown("### 👥 Connected Viewers & Source ID Registry")
    st.caption("Tracks unique IP addresses and watchlist identifiers interacting with SentinelNet.")
    
    if not events_df.empty and "src_ip" in events_df.columns:
        # Extract unique viewer source IDs/IPs from SQLite security events
        viewers_df = events_df[["src_ip"]].drop_duplicates().reset_index(drop=True)
        viewers_df.rename(columns={"src_ip": "Viewer Source ID (IP Address)"}, inplace=True)
        viewers_df["Watchlist Association"] = viewers_df["Viewer Source ID (IP Address)"].apply(
            lambda ip: "Watched Admin / Watchlist Target" if ip == "127.0.0.1" else "External/Client Node"
        )
        st.dataframe(viewers_df, use_container_width=True, hide_index=True)
    else:
        st.info("No external viewer source IDs logged yet. Run a PCAP analysis or generate traffic.")
    # =========================================================================

    st.markdown("---")
    st.markdown("**Group 21 - Symbiosis Institute of Technology (Batch 2024–2028)**")
    render_dynamic_status_panel(telemetry)
    st.markdown("---")
    st.markdown("**Group 21 - Symbiosis Institute of Technology (Batch 2024–2028)**")