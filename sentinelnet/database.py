import sqlite3
from datetime import datetime
import pandas as pd
from config import DB_PATH


class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Raw / Summarized Security Events (Packets/Flows)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_size INTEGER,
                    tcp_flags TEXT,
                    anomaly_score REAL DEFAULT 0.0
                )
            """)

            # Table 2: Triggered Intrusion Alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_score INTEGER NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'OPEN'
                )
            """)

            # Table 3: Automated Threat Response Actions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_id INTEGER,
                    target_ip TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    execution_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts (alert_id)
                )
            """)
            conn.commit()

    def log_event(self, event_data: dict):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_events 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, tcp_flags, anomaly_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                event_data.get("src_ip", "Unknown"),
                event_data.get("dst_ip", "Unknown"),
                event_data.get("src_port", 0),
                event_data.get("dst_port", 0),
                event_data.get("protocol", "OTHER"),
                event_data.get("packet_size", 0),
                event_data.get("tcp_flags", ""),
                event_data.get("anomaly_score", 0.0)
            ))
            conn.commit()

    def log_alert(self, alert_data: dict) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts 
                (timestamp, src_ip, dst_ip, rule_id, alert_type, severity, threat_score, description, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                alert_data["src_ip"],
                alert_data["dst_ip"],
                alert_data["rule_id"],
                alert_data["alert_type"],
                alert_data["severity"],
                alert_data["threat_score"],
                alert_data["description"],
                alert_data.get("status", "OPEN")
            ))
            conn.commit()
            return cursor.lastrowid

    def log_response(self, response_data: dict):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO response_actions 
                (timestamp, alert_id, target_ip, action_taken, execution_mode, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                response_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                response_data.get("alert_id"),
                response_data["target_ip"],
                response_data["action_taken"],
                response_data["execution_mode"],
                response_data["status"]
            ))
            conn.commit()

    def fetch_dataframe(self, table_name: str, limit: int = 500) -> pd.DataFrame:
        allowed_tables = {"security_events", "alerts", "response_actions"}
        if table_name not in allowed_tables:
            raise ValueError(f"Invalid table name: {table_name}")
        with self.get_connection() as conn:
            query = f"SELECT * FROM {table_name} ORDER BY 1 DESC LIMIT {int(limit)}"
            return pd.read_sql_query(query, conn)

    def clear_all_data(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM response_actions")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM security_events")
            conn.commit()