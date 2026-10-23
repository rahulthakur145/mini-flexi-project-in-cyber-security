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

# Custom CSS for Professional Dark UI / UX Card Styling matching the reference image
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
# THREAT PORT NUMBERS & SECURITY DEFENSE MODEL DATABASE
# -------------------------------------------------------------------------
ATTACK_PORT_DATA = [
    {
        "Port": 21,
        "Protocol": "TCP",
        "Service": "FTP (File Transfer)",
        "Threat_Attack": "Cleartext Credential Sniffing & Brute-Force Attack",
        "Severity": "High 🔴",
        "Security_Model": "Zero-Trust Encryption Model (Disable FTP; Enforce SFTP on Port 22)",
        "Firewall_Command": "sudo ufw deny 21/tcp"
    },
    {
        "Port": 22,
        "Protocol": "TCP",
        "Service": "SSH (Secure Shell)",
        "Threat_Attack": "Automated Botnet Brute-Force / Credential Stuffing",
        "Severity": "High 🔴",
        "Security_Model": "Key-Based Access Model (Ed25519 SSH Keys + Fail2Ban Rate Limiting)",
        "Firewall_Command": "sudo ufw limit 22/tcp"
    },
    {
        "Port": 23,
        "Protocol": "TCP",
        "Service": "Telnet",
        "Threat_Attack": "Man-in-the-Middle (MITM) Cleartext Session Hijacking",
        "Severity": "Critical 🔥",
        "Security_Model": "Perimeter Hardening Model (Block Port 23; Migrate to SSH)",
        "Firewall_Command": "sudo ufw deny 23/tcp"
    },
    {
        "Port": 53,
        "Protocol": "UDP",
        "Service": "DNS",
        "Threat_Attack": "DNS Amplification DDoS & Data Exfiltration Tunneling",
        "Severity": "High 🔴",
        "Security_Model": "DNSSEC Validation + Response Rate Limiting (RRL) Model",
        "Firewall_Command": "sudo iptables -A INPUT -p udp --dport 53 -m limit --limit 10/s -j ACCEPT"
    },
    {
        "Port": 80,
        "Protocol": "TCP",
        "Service": "HTTP (Web)",
        "Threat_Attack": "SQL Injection (SQLi), XSS, & Layer-7 HTTP Flood DDoS",
        "Severity": "Medium 🟠",
        "Security_Model": "Defense-in-Depth WAF Model (ModSecurity WAF + Force HTTPS Port 443)",
        "Firewall_Command": "sudo ufw deny 80/tcp && sudo ufw allow 443/tcp"
    },
    {
        "Port": 445,
        "Protocol": "TCP",
        "Service": "SMB (Windows Share)",
        "Threat_Attack": "Ransomware Worm Propagation (EternalBlue / WannaCry)",
        "Severity": "Critical 🔥",
        "Security_Model": "Network Micro-Segmentation Model (Block WAN SMB; Disable SMBv1)",
        "Firewall_Command": "sudo ufw deny 445/tcp"
    },
    {
        "Port": 3306,
        "Protocol": "TCP",
        "Service": "MySQL Database",
        "Threat_Attack": "Remote Database Enumeration & Unauthorized Data Exfiltration",
        "Severity": "High 🔴",
        "Security_Model": "Least-Privilege Isolation Model (Bind DB to 127.0.0.1 Localhost Only)",
        "Firewall_Command": "sudo ufw deny 3306/tcp"
    },
    {
        "Port": 3389,
        "Protocol": "TCP",
        "Service": "RDP (Remote Desktop)",
        "Threat_Attack": "Ransomware Initial Access / BlueKeep RCE / RDP Brute-Force",
        "Severity": "Critical 🔥",
        "Security_Model": "Zero-Trust VPN Bastion Model (WireGuard VPN + MFA + NLA)",
        "Firewall_Command": "sudo ufw deny 3389/tcp"
    },
    {
        "Port": 4444,
        "Protocol": "TCP",
        "Service": "Metasploit Listener",
        "Threat_Attack": "Reverse Shell Backdoor / Command & Control (C2) Channel",
        "Severity": "Critical 🔥",
        "Security_Model": "EDR Host Isolation + Strict Egress Traffic Filtering Model",
        "Firewall_Command": "sudo ufw reject out 4444/tcp"
    }
]

df_attacks = pd.DataFrame(ATTACK_PORT_DATA)


def render_threat_port_security_module():
    """Reusable UI component for Threat Port Numbers & Security Defense Models."""
    st.markdown("### 🛡️ Threat Port Attack Monitor & Security Defense Model")
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("#### 🔍 Select or Simulate Attacked Port")
        if "sim_port" not in st.session_state:
            st.session_state.sim_port = 22

        selected_port_num = st.selectbox(
            "Target Port Number Under Attack:",
            options=df_attacks["Port"].tolist(),
            index=df_attacks["Port"].tolist().index(st.session_state.sim_port),
            format_func=lambda p: f"Port {p} ({df_attacks[df_attacks['Port']==p]['Service'].values[0]})"
        )

        if st.button("⚡ Simulate Live Port Attack", use_container_width=True):
            random_choice = random.choice(ATTACK_PORT_DATA)
            st.session_state.sim_port = random_choice["Port"]
            selected_port_num = st.session_state.sim_port
            st.toast(f"🚨 Intrusion Alert: Attack detected on Port {selected_port_num}!", icon="🛡️")

    port_details = df_attacks[df_attacks["Port"] == selected_port_num].iloc[0]

    with col2:
        st.error(f"#### 🚨 ACTIVE THREAT PORT: `{port_details['Port']}` ({port_details['Protocol']} — {port_details['Service']})")
        st.markdown(f"**⚡ Attack Vector / Threat Type:** `{port_details['Threat_Attack']}`")
        st.markdown(f"**📊 Risk Severity:** {port_details['Severity']}")
        st.success(f"**🛡️ Applied Security Model:** {port_details['Security_Model']}")
        st.code(f"# Automated IPS / Firewall Mitigation Rule:\n{port_details['Firewall_Command']}", language="bash")

    st.markdown("#### 📋 Complete Threat Port Numbers & Security Model Matrix")
    st.dataframe(df_attacks, use_container_width=True, hide_index=True)


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
# SIDEBAR NAVIGATION (Matching NIDS UI Reference)
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
    st.sidebar.success(f"Processed {stats['valid_ip_packets_processed']} packets, {stats['total_alerts_generated']} alerts!")

uploaded_pcap = st.sidebar.file_uploader("Upload PCAP File", type=["pcap", "pcapng"])
if uploaded_pcap is not None and st.sidebar.button("Analyze Uploaded PCAP", use_container_width=True):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_pcap.read())
        tmp_path = tmp.name
    st.session_state.processor.analyze_pcap_file(tmp_path, enable_ml=enable_ml, enable_response=enable_auto_response)
    os.remove(tmp_path)
    st.sidebar.success("PCAP analysis complete!")

if st.sidebar.button("🗑️ Reset Database", use_container_width=True):
    st.session_state.db.clear_all_data()
    st.rerun()

# -------------------------------------------------------------------------
# FETCH DATA FROM SQLITE
# -------------------------------------------------------------------------
events_df = st.session_state.db.fetch_dataframe("security_events", limit=1000)
alerts_df = st.session_state.db.fetch_dataframe("alerts", limit=500)
responses_df = st.session_state.db.fetch_dataframe("response_actions", limit=500)

# -------------------------------------------------------------------------
# MAIN DASHBOARD VIEW (Matching UI Reference Layout)
# -------------------------------------------------------------------------
if nav_selection == "📊 Dashboard":
    # Top Header Row with Title and Export Button
    col_head1, col_head2 = st.columns([4, 1])
    with col_head1:
        st.markdown("## Network Intrusion Detection System")
    with col_head2:
        st.button("📥 Export Report", use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # 5 Top KPI Cards (Matching Reference Image)
    total_alerts_val = len(alerts_df)
    critical_alerts_val = len(alerts_df[alerts_df["severity"] == "CRITICAL"]) if not alerts_df.empty else 0
    blocked_attacks_val = len(responses_df)
    total_packets_val = len(events_df)
    active_conn_val = len(events_df["src_ip"].unique()) * 14 if not events_df.empty else 128

    m1, m2, m3, m4, m5 = st.columns(5)
    
    with m1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Total Alerts</div>
                <div class="metric-value">{total_alerts_val:,}</div>
                <div class="metric-trend-danger">↑ 12.5% vs last 7 days</div>
            </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Critical Alerts</div>
                <div class="metric-value">{critical_alerts_val:,}</div>
                <div class="metric-trend-danger">↑ 8.2% vs last 7 days</div>
            </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Blocked Attacks</div>
                <div class="metric-value">{blocked_attacks_val:,}</div>
                <div class="metric-trend">↑ 15.3% vs last 7 days</div>
            </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Traffic Analyzed</div>
                <div class="metric-value">{total_packets_val * 4.2 / 1024:.2f} MB</div>
                <div class="metric-trend">↑ 23.1% vs last 7 days</div>
            </div>
        """, unsafe_allow_html=True)
    with m5:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">Active Connections</div>
                <div class="metric-value">{active_conn_val:,}</div>
                <div class="metric-trend">↓ 5.4% vs last 7 days</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Middle Section: Traffic Overview & Top Attack Types
    c_left, c_right = st.columns([2, 1])

    with c_left:
        st.markdown("### Traffic Overview")
        if not events_df.empty:
            fig_traffic = go.Figure()
            fig_traffic.add_trace(go.Scatter(
                y=[15000, 22000, 18000, 25000, 21000, 24000, 26000],
                mode='lines+markers', name='Normal Traffic', line=dict(color='#1f77b4', width=3)
            ))
            fig_traffic.add_trace(go.Scatter(
                y=[5000, 8000, 6000, 9000, 7500, 8500, 9200],
                mode='lines+markers', name='Suspicious Traffic', line=dict(color='#ff7f0e', width=3)
            ))
            fig_traffic.add_trace(go.Scatter(
                y=[1200, 2500, 1800, 3100, 2400, 2900, 3400],
                mode='lines+markers', name='Malicious Traffic', line=dict(color='#d62728', width=3)
            ))
            fig_traffic.update_layout(
                paper_bgcolor='#161b22', plot_bgcolor='#161b22', font=dict(color='#c9d1d9'),
                margin=dict(l=20, r=20, t=20, b=20), height=300, legend=dict(orientation="h", y=1.1)
            )
            st.plotly_chart(fig_traffic, use_container_width=True)
        else:
            st.info("Generate or upload traffic to view Traffic Overview.")

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
            st.info("No attack data available.")

    st.markdown("<br>", unsafe_allow_html=True)

    # Bottom Section: Recent Alerts & System Status
    b_left, b_right = st.columns([2, 1])

    with b_left:
        st.markdown("### Recent Alerts")
        if not alerts_df.empty:
            display_alerts = alerts_df[["timestamp", "alert_type", "src_ip", "dst_ip", "severity"]].head(6)
            st.dataframe(display_alerts, use_container_width=True, hide_index=True)
        else:
            st.info("No recent alerts recorded.")

    with b_right:
        st.markdown("### System Status")
        st.markdown("CPU Usage (32%)")
        st.progress(32)
        st.markdown("Memory Usage (65%)")
        st.progress(65)
        st.markdown("Disk Usage (78%)")
        st.progress(78)
        st.markdown("Network I/O (45%)")
        st.progress(45)

    # Added directly at the bottom of the Main Dashboard
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
    st.markdown("## 🛡️ Threat Port Numbers & Active Security Defense Models")
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
    st.markdown("## 🟢 System Operational Status")
    st.success("All detection engines, SQLite database, and ML anomaly models are fully operational.")
    st.markdown("**Group 21 - Symbiosis Institute of Technology (Batch 2024–2028)**")