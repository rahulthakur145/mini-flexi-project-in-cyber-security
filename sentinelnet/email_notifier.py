import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


class EmailAlertNotifier:
    def __init__(self):
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = ""
        self.sender_app_password = ""
        self.recipient_emails = []
        self.enabled = False

    def configure(self, sender_email: str, app_password: str, recipients_str: str, enabled: bool):
        self.sender_email = sender_email.strip()
        self.sender_app_password = app_password.strip().replace(" ", "")
        self.recipient_emails = [
            r.strip() for r in recipients_str.split(",") if r.strip() and "@" in r
        ]
        self.enabled = enabled

    def send_intrusion_alert(self, alert_data: dict) -> dict:
        """
        Sends an automated email alert via Gmail SMTP for HIGH or CRITICAL threats.
        Falls back to Simulated Email Log if App Password isn't provided, so your demo never fails!
        """
        if not self.enabled or not self.recipient_emails:
            return {"status": "DISABLED", "message": "Email notifications not enabled."}

        subject = f"[SentinelNet {alert_data['severity']} ALERT] {alert_data['alert_type']} Detected!"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #222;">
            <h2 style="color: #d62728;">🛡️ SentinelNet Intrusion Detection Alert</h2>
            <p>An active security threat was detected on your monitored network:</p>
            <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 600px;">
                <tr><td><b>Timestamp</b></td><td>{alert_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</td></tr>
                <tr><td><b>Alert Type</b></td><td>{alert_data['alert_type']}</td></tr>
                <tr><td><b>Rule ID</b></td><td>{alert_data['rule_id']}</td></tr>
                <tr><td><b>Severity</b></td><td style="color: red;"><b>{alert_data['severity']} (Score: {alert_data['threat_score']}/100)</b></td></tr>
                <tr><td><b>Attacker Source IP</b></td><td>{alert_data['src_ip']}</td></tr>
                <tr><td><b>Target Destination IP</b></td><td>{alert_data['dst_ip']}</td></tr>
                <tr><td><b>Details</b></td><td>{alert_data['description']}</td></tr>
            </table>
            <p style="margin-top: 15px; font-size: 12px; color: #666;">
                Generated automatically by SentinelNet IDS/IPS — Symbiosis Institute of Technology (Group 21).
            </p>
        </body>
        </html>
        """

        # If sender credentials aren't configured yet, log a simulated email dispatch for smooth lab testing
        if not self.sender_email or not self.sender_app_password:
            return {
                "status": "SIMULATED_SENT",
                "recipients": ", ".join(self.recipient_emails),
                "subject": subject,
                "message": f"Simulated email alert queued for {', '.join(self.recipient_emails)}"
            }

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(self.recipient_emails)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_app_password)
                server.sendmail(self.sender_email, self.recipient_emails, msg.as_string())

            return {
                "status": "SENT_REAL_EMAIL",
                "recipients": ", ".join(self.recipient_emails),
                "subject": subject,
                "message": f"Live Gmail alert sent to {', '.join(self.recipient_emails)}"
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "recipients": ", ".join(self.recipient_emails),
                "subject": subject,
                "message": f"SMTP Error: {str(e)}"
            }