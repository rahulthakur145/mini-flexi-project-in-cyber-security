import platform
import subprocess
from datetime import datetime
from config import ENABLE_ACTIVE_FIREWALL_BLOCK, WHITELISTED_IPS


class AutomatedResponder:
    def __init__(self, db_manager):
        self.db = db_manager
        self.blocked_ips = set()

    def evaluate_and_respond(self, alert_id: int, alert_data: dict, force_simulation: bool = True) -> dict | None:
        """
        Triggers automated IP blocking if threat_score >= 75 (HIGH or CRITICAL).
        """
        src_ip = alert_data["src_ip"]
        threat_score = alert_data["threat_score"]

        if threat_score < 75:
            return None

        if src_ip in WHITELISTED_IPS:
            response_record = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_id": alert_id,
                "target_ip": src_ip,
                "action_taken": "SKIPPED (Whitelisted IP)",
                "execution_mode": "SAFE_GUARD",
                "status": "IGNORED"
            }
            self.db.log_response(response_record)
            return response_record

        if src_ip in self.blocked_ips:
            return None

        os_type = platform.system()
        if os_type == "Linux":
            cmd = ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
            cmd_str = f"sudo iptables -A INPUT -s {src_ip} -j DROP"
        elif os_type == "Windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=SentinelNet_Block_{src_ip}", "dir=in", "action=block", f"remoteip={src_ip}"
            ]
            cmd_str = f"netsh advfirewall firewall add rule name=SentinelNet_Block_{src_ip} dir=in action=block remoteip={src_ip}"
        else:
            cmd = []
            cmd_str = f"pfctl -t sentinelnet_block -T add {src_ip}"

        # Execute in Simulation Mode unless explicitly enabled in config AND UI
        if force_simulation or not ENABLE_ACTIVE_FIREWALL_BLOCK:
            self.blocked_ips.add(src_ip)
            response_record = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_id": alert_id,
                "target_ip": src_ip,
                "action_taken": f"Block Rule: `{cmd_str}`",
                "execution_mode": "SIMULATION_ONLY",
                "status": "LOGGED_SIMULATED_BLOCK"
            }
            self.db.log_response(response_record)
            return response_record

        # Active Execution inside Isolated Lab Environment
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5)
            self.blocked_ips.add(src_ip)
            status = "APPLIED_FIREWALL_RULE"
        except Exception as e:
            status = f"FAILED ({type(e).__name__})"

        response_record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_id": alert_id,
            "target_ip": src_ip,
            "action_taken": f"Executed: `{cmd_str}`",
            "execution_mode": "ACTIVE_ENFORCEMENT",
            "status": status
        }
        self.db.log_response(response_record)
        return response_record