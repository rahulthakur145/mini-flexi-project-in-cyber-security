import os
import tempfile
import streamlit as st
import pandas as pd
import plotly.express as px

from config import SAMPLE_PCAP_PATH
from database import DatabaseManager
from rules_engine import RuleEngine
from ml_analyzer import BehavioralMLAnalyzer
from responder import AutomatedResponder
from email_notifier import EmailAlertNotifier
from packet_processor import PacketProcessor
from traffic_simulator import generate_test_pcap

st.set_page_config(
    page_title="SentinelNet IDS/IPS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Initialize Core Singletons in Streamlit Session State
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

# Header
st.title("🛡️ SentinelNet: Intelligent Network Intrusion Detection & Threat Response")
st.caption(
    "Symbiosis Institute of Technology | Dept. of Computer Science & Engineering | "
    "Group 21 (CSE-B, Batch 2024–2028)"
)

# Sidebar Controls
st.sidebar.header("⚙️ Control Panel")
enable_ml = st.sidebar.checkbox("Enable Behavioral ML (Isolation Forest)", value=True)
enable_auto_response = st.sidebar.checkbox("Enable Automated Threat Response (Simulated Block)", value=True)

# -------------------------------------------------------------------------
# NEW SECTION: GMAIL ID WATCHLIST & EMAIL ALERT NOTIFICATIONS
# -------------------------------------------------------------------------
st.sidebar.markdown("---")
st.sidebar.subheader("📧 Gmail ID Detection & Alerts")

monitored_gmails = st.sidebar.text_input(
    "1. Watchlist Gmail IDs (Detect in Traffic)",
    value="student.sit@gmail.com",
    help="Enter one or more Gmail IDs (comma-separated) to detect if they appear in unencrypted network traffic or credential leaks."
)
st.session_state.processor.set_monitored_gmails(monitored_gmails)

enable_email_alerts = st.sidebar.checkbox("2. Send Alert Notifications to Gmail", value=True)
recipient_gmails = st.sidebar.text_input(
    "Recipient Gmail ID(s) for Threat Alerts",
    value=monitored_gmails,
    help="Comma-separated Gmail addresses that will receive HIGH/CRITICAL intrusion alerts."
)

with st.sidebar.expander("🔐 Optional: Live Gmail SMTP Credentials"):
    st.caption("Leave blank for Simulated Email Dispatch, or enter a Gmail + 16-digit Google App Password to send real emails.")
    smtp_sender = st.text_input("Sender Gmail Address", value="")
    smtp_app_pass = st.text_input("Google App Password (16 chars)", value="", type="password")

st.session_state.email_notifier.configure(
    sender_email=smtp_sender,
    app_password=smtp_app_pass,
    recipients_str=recipient_gmails,
    enabled=enable_email_alerts
)

# -------------------------------------------------------------------------
# TRAFFIC CAPTURE & SIMULATION CONTROLS
# -------------------------------------------------------------------------
st.sidebar.markdown("---")
st.sidebar.subheader("1. Laboratory Simulation (Recommended)")
if st.sidebar.button("🚀 Generate & Analyze Lab Test PCAP", use_container_width=True):
    with st.spinner("Synthesizing multi-scenario PCAP and running detection engine..."):
        sim_info = generate_test_pcap(SAMPLE_PCAP_PATH, test_gmail=monitored_gmails)
        stats = st.session_state.processor.analyze_pcap_file(
            SAMPLE_PCAP_PATH,
            enable_ml=enable_ml,
            enable_response=enable_auto_response
        )
    st.sidebar.success(
        f"Processed {stats['valid_ip_packets_processed']} packets! "
        f"Triggered {stats['total_alerts_generated']} security alerts."
    )

st.sidebar.subheader("2. Upload Custom PCAP File")
uploaded_pcap = st.sidebar.file_uploader("Upload `.pcap` or `.pcapng`", type=["pcap", "pcapng"])
if uploaded_pcap is not None:
    if st.sidebar.button("🔍 Analyze Uploaded PCAP", use_container_width=True):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            tmp_file.write(uploaded_pcap.read())
            tmp_path = tmp_file.name
        with st.spinner("Analyzing uploaded packet capture..."):
            stats = st.session_state.processor.analyze_pcap_file(
                tmp_path,
                enable_ml=enable_ml,
                enable_response=enable_auto_response
            )
        os.remove(tmp_path)
        st.sidebar.success(
            f"Analyzed {stats['valid_ip_packets_processed']} packets. "
            f"Generated {stats['total_alerts_generated']} alerts."
        )

st.sidebar.subheader("3. Live Interface Capture")
iface_name = st.sidebar.text_input("Network Interface (blank = default)", value="")
pkt_limit = st.sidebar.slider("Packet Capture Count", min_value=10, max_value=200, value=40)
if st.sidebar.button("📡 Capture Live Traffic", use_container_width=True):
    try:
        with st.spinner(f"Sniffing up to {pkt_limit} packets (15s timeout)..."):
            live_stats = st.session_state.processor.capture_live_packets(
                interface=iface_name.strip() or None,
                packet_count=pkt_limit,
                timeout=15,
                enable_ml=enable_ml
            )
        st.sidebar.success(
            f"Captured {live_stats['processed_count']} IP packets, "
            f"{live_stats['alerts_generated']} alerts triggered."
        )
    except PermissionError:
        st.sidebar.error(
            "Permission denied! Live packet sniffing requires Administrator / sudo privileges. "
            "Use 'Generate & Analyze Lab Test PCAP' or run terminal as root/Admin."
        )
    except Exception as e:
        st.sidebar.error(f"Capture error: {e}")

st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Reset Database & Counters", use_container_width=True):
    st.session_state.db.clear_all_data()
    st.session_state.rule_engine = RuleEngine()
    st.session_state.responder = AutomatedResponder(st.session_state.db)
    st.session_state.processor.rule_engine = st.session_state.rule_engine
    st.session_state.processor.responder = st.session_state.responder
    st.session_state.processor.email_logs = []
    st.rerun()

# Fetch Current Data from SQLite
events_df = st.session_state.db.fetch_dataframe("security_events", limit=1000)
alerts_df = st.session_state.db.fetch_dataframe("alerts", limit=500)
responses_df = st.session_state.db.fetch_dataframe("response_actions", limit=500)

# Top KPI Metrics Row
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Packets Analyzed", len(events_df))
col2.metric("Total Intrusion Alerts", len(alerts_df))
high_crit_count = len(alerts_df[alerts_df["severity"].isin(["HIGH", "CRITICAL"])]) if not alerts_df.empty else 0
col3.metric("High / Critical Threats", high_crit_count)
col4.metric("Automated Block Actions", len(responses_df))

st.markdown("---")

# Main Dashboard Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Security Overview & Charts",
    "🚨 Intrusion Alerts & Automated Response",
    "📦 Packet Inspection Log",
    "📈 Performance Evaluation Calculator"
])

with tab1:
    if alerts_df.empty and events_df.empty:
        st.info("No network traffic analyzed yet. Click **'🚀 Generate & Analyze Lab Test PCAP'** in the left sidebar to populate the dashboard.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Alert Distribution by Severity")
            if not alerts_df.empty:
                fig_sev = px.pie(
                    alerts_df,
                    names="severity",
                    color="severity",
                    color_discrete_map={
                        "CRITICAL": "#d62728",
                        "HIGH": "#ff7f0e",
                        "MEDIUM": "#ffbb78",
                        "LOW": "#1f77b4"
                    },
                    hole=0.4
                )
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.write("No alerts triggered.")

        with c2:
            st.subheader("Alerts by Detection Rule / Attack Type")
            if not alerts_df.empty:
                rule_counts = alerts_df["alert_type"].value_counts().reset_index()
                rule_counts.columns = ["Attack Type", "Count"]
                fig_bar = px.bar(
                    rule_counts,
                    x="Attack Type",
                    y="Count",
                    color="Attack Type",
                    text_auto=True
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.write("No alerts triggered.")

        st.subheader("Protocol & Anomaly Score Distribution")
        if not events_df.empty:
            fig_scatter = px.scatter(
                events_df,
                x="dst_port",
                y="packet_size",
                color="protocol",
                size="anomaly_score",
                hover_data=["src_ip", "dst_ip", "tcp_flags", "anomaly_score"],
                labels={"dst_port": "Destination Port", "packet_size": "Packet Size (Bytes)"}
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

with tab2:
    st.subheader("🚨 Triggered Security Alerts")
    if not alerts_df.empty:
        st.dataframe(alerts_df, use_container_width=True, hide_index=True)
    else:
        st.info("No active alerts in database.")

    st.subheader("📧 Gmail Alert Notification Log")
    if st.session_state.processor.email_logs:
        st.dataframe(pd.DataFrame(st.session_state.processor.email_logs), use_container_width=True, hide_index=True)
    else:
        st.info("No Gmail alerts dispatched yet.")

    st.subheader("🛡️ Automated Threat Response Log (Firewall Actions)")
    if not responses_df.empty:
        st.dataframe(responses_df, use_container_width=True, hide_index=True)
    else:
        st.info("No automated response actions recorded yet.")

with tab3:
    st.subheader("📦 Captured Packet & Feature Log (SQLite `security_events`)")
    if not events_df.empty:
        st.dataframe(events_df, use_container_width=True, hide_index=True)
    else:
        st.info("No packets logged yet.")

with tab4:
    st.subheader("📈 Experimental Detection Metrics Calculator (Chapter 15)")
    st.markdown(
        "Use this calculator during laboratory testing to compute **Precision**, **Recall**, "
        "**False-Positive Rate (FPR)**, and **F1-Score** from your test cases."
    )
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    tp = mcol1.number_input("True Positives (TP)", min_value=0, value=5)
    fp = mcol2.number_input("False Positives (FP)", min_value=0, value=0)
    fn = mcol3.number_input("False Negatives (FN)", min_value=0, value=0)
    tn = mcol4.number_input("True Negatives (TN)", min_value=0, value=50)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    rcol1, rcol2, rcol3, rcol4 = st.columns(4)
    rcol1.metric("Precision", f"{precision * 100:.2f}%")
    rcol2.metric("Recall (Sensitivity)", f"{recall * 100:.2f}%")
    rcol2.metric("False-Positive Rate (FPR)", f"{fpr * 100:.2f}%")
    rcol4.metric("F1-Score", f"{f1_score * 100:.2f}%")