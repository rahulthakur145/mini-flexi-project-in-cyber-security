from collections import defaultdict, deque
from config import (
    TIME_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
    TRAFFIC_SPIKE_THRESHOLD,
    BRUTE_FORCE_THRESHOLD,
    SENSITIVE_PORTS,
    SEVERITY_LEVELS
)


class RuleEngine:
    def __init__(self):
        # Sliding window queues keyed by source IP
        self.port_scan_tracker = defaultdict(deque)     # stores (timestamp, dst_port)
        self.syn_flood_tracker = defaultdict(deque)     # stores timestamp
        self.brute_force_tracker = defaultdict(deque)   # stores (timestamp, dst_port)
        self.traffic_rate_tracker = defaultdict(deque)  # stores timestamp

        # Cooldown tracker so identical alerts aren't spammed on every single packet
        self.alert_cooldown = {}
        self.cooldown_seconds = 10

    def _prune_old_entries(self, queue: deque, current_ts: float):
        while queue and (current_ts - queue[0][0] if isinstance(queue[0], tuple) else current_ts - queue[0]) > TIME_WINDOW_SECONDS:
            queue.popleft()

    def _can_trigger(self, src_ip: str, rule_id: str, current_ts: float) -> bool:
        key = (src_ip, rule_id)
        last_triggered = self.alert_cooldown.get(key, -9999)
        if (current_ts - last_triggered) >= self.cooldown_seconds:
            self.alert_cooldown[key] = current_ts
            return True
        return False

    def evaluate_packet(self, pkt_features: dict) -> list:
        """
        Evaluates extracted packet features against Stateful & Stateless Rules.
        Returns a list of triggered alert dictionaries.
        """
        alerts = []
        src_ip = pkt_features["src_ip"]
        dst_ip = pkt_features["dst_ip"]
        dst_port = pkt_features["dst_port"]
        protocol = pkt_features["protocol"]
        tcp_flags = pkt_features["tcp_flags"]
        pkt_ts = pkt_features["epoch_ts"]
        timestamp_str = pkt_features["timestamp"]

        # -----------------------------------------------------------------
        # RULE-001: Port Scanning Detection (Distinct Ports in Time Window)
        # -----------------------------------------------------------------
        if dst_port > 0:
            q_ports = self.port_scan_tracker[src_ip]
            q_ports.append((pkt_ts, dst_port))
            self._prune_old_entries(q_ports, pkt_ts)
            unique_ports = {p for _, p in q_ports}

            if len(unique_ports) >= PORT_SCAN_THRESHOLD and self._can_trigger(src_ip, "SN-RULE-001", pkt_ts):
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-001",
                    "alert_type": "Port Scan Detected",
                    "severity": "HIGH",
                    "threat_score": SEVERITY_LEVELS["HIGH"],
                    "description": f"Host {src_ip} scanned {len(unique_ports)} distinct ports on {dst_ip} within {TIME_WINDOW_SECONDS}s."
                })

        # -----------------------------------------------------------------
        # RULE-002: Repeated Connection / Brute-Force Indicator on Sensitive Ports
        # -----------------------------------------------------------------
        if dst_port in SENSITIVE_PORTS and ("S" in tcp_flags or protocol == "TCP"):
            q_bf = self.brute_force_tracker[src_ip]
            q_bf.append((pkt_ts, dst_port))
            self._prune_old_entries(q_bf, pkt_ts)
            service_attempts = [p for _, p in q_bf if p == dst_port]

            if len(service_attempts) >= BRUTE_FORCE_THRESHOLD and self._can_trigger(src_ip, f"SN-RULE-002-{dst_port}", pkt_ts):
                service_name = SENSITIVE_PORTS[dst_port]
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-002",
                    "alert_type": f"Repeated {service_name} Connection Attempts",
                    "severity": "HIGH",
                    "threat_score": SEVERITY_LEVELS["HIGH"],
                    "description": f"{len(service_attempts)} rapid connection attempts to {service_name} (Port {dst_port}) from {src_ip}."
                })

        # -----------------------------------------------------------------
        # RULE-003: TCP SYN Flood / Half-Open Connection Burst
        # -----------------------------------------------------------------
        if protocol == "TCP" and tcp_flags == "S":
            q_syn = self.syn_flood_tracker[src_ip]
            q_syn.append(pkt_ts)
            self._prune_old_entries(q_syn, pkt_ts)

            if len(q_syn) >= SYN_FLOOD_THRESHOLD and self._can_trigger(src_ip, "SN-RULE-003", pkt_ts):
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-003",
                    "alert_type": "TCP SYN Flood / DoS Indicator",
                    "severity": "CRITICAL",
                    "threat_score": SEVERITY_LEVELS["CRITICAL"],
                    "description": f"Excessive SYN packets ({len(q_syn)} in {TIME_WINDOW_SECONDS}s) from {src_ip} targeting {dst_ip}."
                })

        # -----------------------------------------------------------------
        # RULE-004: Abnormal Volumetric Traffic Spike
        # -----------------------------------------------------------------
        q_rate = self.traffic_rate_tracker[src_ip]
        q_rate.append(pkt_ts)
        self._prune_old_entries(q_rate, pkt_ts)

        if len(q_rate) >= TRAFFIC_SPIKE_THRESHOLD and self._can_trigger(src_ip, "SN-RULE-004", pkt_ts):
            alerts.append({
                "timestamp": timestamp_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "rule_id": "SN-RULE-004",
                "alert_type": "Abnormal Traffic Rate Spike",
                "severity": "MEDIUM",
                "threat_score": SEVERITY_LEVELS["MEDIUM"],
                "description": f"High packet rate ({len(q_rate)} packets/{TIME_WINDOW_SECONDS}s) observed from {src_ip}."
            })

        # -----------------------------------------------------------------
        # RULE-005: Suspicious TCP Flag Combinations (Null / Xmas Scan)
        # -----------------------------------------------------------------
        if protocol == "TCP":
            if tcp_flags == "" and self._can_trigger(src_ip, "SN-RULE-005-NULL", pkt_ts):
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-005",
                    "alert_type": "Malformed TCP Null Scan",
                    "severity": "MEDIUM",
                    "threat_score": SEVERITY_LEVELS["MEDIUM"],
                    "description": f"TCP packet with no flags set (Null Scan) from {src_ip} to port {dst_port}."
                })
            elif all(flag in tcp_flags for flag in ["F", "P", "U"]) and self._can_trigger(src_ip, "SN-RULE-005-XMAS", pkt_ts):
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-005",
                    "alert_type": "TCP Xmas Scan Pattern",
                    "severity": "HIGH",
                    "threat_score": SEVERITY_LEVELS["HIGH"],
                    "description": f"TCP FIN-PSH-URG (Xmas tree) packet detected from {src_ip} to port {dst_port}."
                })
                # -----------------------------------------------------------------
        # RULE-007: Gmail / Mail Server Brute-Force & Credential Stuffing
        # -----------------------------------------------------------------
        if dst_port in {465, 587, 993, 995} and ("S" in tcp_flags or protocol == "TCP"):
            q_mail = self.brute_force_tracker[f"mail_{src_ip}"]
            q_mail.append((pkt_ts, dst_port))
            self._prune_old_entries(q_mail, pkt_ts)

            if len(q_mail) >= 6 and self._can_trigger(src_ip, f"SN-RULE-007-{dst_port}", pkt_ts):
                alerts.append({
                    "timestamp": timestamp_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "rule_id": "SN-RULE-007",
                    "alert_type": "Gmail / Mail Server Brute-Force Attack",
                    "severity": "CRITICAL",
                    "threat_score": 95,
                    "description": f"Rapid authentication / connection burst ({len(q_mail)} attempts) targeting secure mail port {dst_port} from {src_ip}, indicating a Gmail credential brute-force attack."
                })

        return alerts