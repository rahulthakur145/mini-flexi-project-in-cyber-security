from datetime import datetime
from scapy.all import rdpcap, sniff, conf, IP, TCP, UDP, ICMP, Raw
from config import SEVERITY_LEVELS


class PacketProcessor:
    def __init__(self, db_manager, rule_engine, ml_analyzer, responder, email_notifier=None):
        self.db = db_manager
        self.rule_engine = rule_engine
        self.ml_analyzer = ml_analyzer
        self.responder = responder
        self.email_notifier = email_notifier
        self.monitored_gmail_ids = set()
        self.email_logs = []

    def set_monitored_gmails(self, gmail_list_str: str):
        """Updates the watchlist of Gmail IDs to inspect inside network traffic payloads."""
        self.monitored_gmail_ids = {
            g.strip().lower() for g in gmail_list_str.split(",") if g.strip() and "@" in g
        }

    def extract_features(self, pkt) -> dict | None:
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        pkt_time = float(pkt.time)
        timestamp_str = datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S")

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        payload_text = ""

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        if pkt.haslayer(Raw):
            try:
                payload_text = pkt[Raw].load.decode("utf-8", errors="ignore").lower()
            except Exception:
                payload_text = ""

        return {
            "epoch_ts": pkt_time,
            "timestamp": timestamp_str,
            "src_ip": str(ip_layer.src),
            "dst_ip": str(ip_layer.dst),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": len(pkt),
            "tcp_flags": tcp_flags,
            "payload_text": payload_text
        }

    def process_single_packet(self, pkt, enable_ml: bool = True, enable_response: bool = True) -> dict:
        features = self.extract_features(pkt)
        if not features:
            return {"processed": False, "alerts_triggered": 0}

        # 1. Standard Rule-Based Detection
        triggered_alerts = self.rule_engine.evaluate_packet(features)

        # 2. Check if any Monitored Gmail ID is exposed or targeted in the packet payload
        payload = features.get("payload_text", "")
        if payload and self.monitored_gmail_ids:
            for gmail_id in self.monitored_gmail_ids:
                if gmail_id in payload:
                    triggered_alerts.append({
                        "timestamp": features["timestamp"],
                        "src_ip": features["src_ip"],
                        "dst_ip": features["dst_ip"],
                        "rule_id": "SN-RULE-006",
                        "alert_type": "Monitored Gmail ID Detected in Traffic",
                        "severity": "CRITICAL",
                        "threat_score": SEVERITY_LEVELS["CRITICAL"],
                        "description": (
                            f"Target Gmail ID '{gmail_id}' detected in unencrypted {features['protocol']} "
                            f"packet payload from {features['src_ip']} to {features['dst_ip']}:{features['dst_port']}."
                        )
                    })

        # 3. Behavioral ML Anomaly Scoring
        anomaly_score = 0.0
        if enable_ml:
            anomaly_score, ml_alert = self.ml_analyzer.score_packet(features)
            if ml_alert:
                triggered_alerts.append(ml_alert)

        features["anomaly_score"] = anomaly_score

        # 4. Log Packet Event to Database
        self.db.log_event(features)

        # 5. Log Alerts, Trigger Firewall Block & Send Gmail Alert Notification
        for alert in triggered_alerts:
            alert_id = self.db.log_alert(alert)
            if enable_response:
                self.responder.evaluate_and_respond(alert_id, alert, force_simulation=True)

            if self.email_notifier and alert["severity"] in ("HIGH", "CRITICAL"):
                mail_res = self.email_notifier.send_intrusion_alert(alert)
                if mail_res["status"] != "DISABLED":
                    self.email_logs.append({
                        "timestamp": alert["timestamp"],
                        "alert_type": alert["alert_type"],
                        "severity": alert["severity"],
                        "recipients": mail_res.get("recipients", ""),
                        "status": mail_res["status"],
                        "details": mail_res["message"]
                    })

        return {
            "processed": True,
            "alerts_triggered": len(triggered_alerts)
        }

    def analyze_pcap_file(self, pcap_path: str, enable_ml: bool = True, enable_response: bool = True) -> dict:
        packets = rdpcap(pcap_path)
        total_processed = 0
        total_alerts = 0

        for pkt in packets:
            res = self.process_single_packet(pkt, enable_ml=enable_ml, enable_response=enable_response)
            if res["processed"]:
                total_processed += 1
                total_alerts += res["alerts_triggered"]

        return {
            "total_packets_in_file": len(packets),
            "valid_ip_packets_processed": total_processed,
            "total_alerts_generated": total_alerts
        }

    def capture_live_packets(self, interface: str = None, packet_count: int = 50, timeout: int = 15, enable_ml: bool = True):
        iface_arg = interface if interface else None
        try:
            captured = sniff(iface=iface_arg, count=packet_count, timeout=timeout)
        except RuntimeError as e:
            if "winpcap is not installed" in str(e).lower() or "layer 2" in str(e).lower():
                captured = sniff(
                    opened_socket=conf.L3socket(iface=iface_arg),
                    count=packet_count,
                    timeout=timeout
                )
            else:
                raise e

        total_processed = 0
        total_alerts = 0

        for pkt in captured:
            res = self.process_single_packet(pkt, enable_ml=enable_ml, enable_response=True)
            if res["processed"]:
                total_processed += 1
                total_alerts += res["alerts_triggered"]

        return {
            "captured_count": len(captured),
            "processed_count": total_processed,
            "alerts_generated": total_alerts
        }