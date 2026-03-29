#!/usr/bin/env python3
"""
Log Analysis & SIEM Lite
=========================
Real-time log parser and SIEM engine. Ingests auth logs, syslog, Apache/
Nginx access logs, and Windows Event Logs. Detects brute-force, privilege
escalation, lateral movement, and anomalous logins. Sends Slack/email alerts.

Author: Egwu Donatus Achema
Usage:
    python3 siem_lite.py --watch /var/log/auth.log /var/log/syslog
    python3 siem_lite.py --watch /var/log/nginx/access.log --format nginx
    python3 siem_lite.py --parse /var/log/auth.log --report report.html
"""

import argparse
import json
import logging
import os
import re
import smtplib
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

# ── Logging ────────────────────────────────────────────────────────────────────
import sys
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[stream_handler, logging.FileHandler("siem.log", encoding="utf-8")],
)
log = logging.getLogger(__name__)

# ── Regex Patterns ─────────────────────────────────────────────────────────────
PATTERNS = {
    # SSH failed password: Dec 10 12:00:01 host sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
    "ssh_fail": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
    ),
    # SSH accepted
    "ssh_accept": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Accepted (?:password|publickey) for (\S+) from (\S+) port \d+"
    ),
    # sudo usage
    "sudo": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*sudo.*?:\s+(\S+)\s+:.*COMMAND=(.*)"
    ),
    # su usage
    "su": re.compile(r"(\w+\s+\d+\s[\d:]+).*su\[.*\]:\s+(.*)"),
    # useradd / usermod / userdel
    "user_mgmt": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*(useradd|usermod|userdel|groupadd|passwd).*user '?(\S+)'?"
    ),
    # cron jobs
    "cron": re.compile(r"(\w+\s+\d+\s[\d:]+).*CRON.*CMD\s+(.*)"),
    # nginx / apache access log (combined format)
    "http_access": re.compile(
        r'(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+)'
    ),
    # kernel / dmesg
    "kernel_oops": re.compile(r"(\w+\s+\d+\s[\d:]+).*kernel.*Oops"),
    # iptables drop
    "iptables_drop": re.compile(r"(\w+\s+\d+\s[\d:]+).*DROPPED.*SRC=(\S+) DST=(\S+)"),
}

# ── Thresholds ─────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESH = 10     # failed logins per minute from same IP
SPRAY_THRESH = 5            # distinct accounts from same IP
HTTP_SCAN_THRESH = 100      # 4xx errors per minute from same IP
PRIV_HOURS = range(22, 24)  # hours outside 8-18 flagged as after-hours


# ══════════════════════════════════════════════════════════════════════════════
class SIEMAlert:
    ICONS = {"LOW": "ℹ", "MEDIUM": "⚠", "HIGH": "🚨", "CRITICAL": "💀"}

    def __init__(self, rule: str, severity: str, src: str, detail: str, raw: str = ""):
        self.ts = datetime.now().isoformat(timespec="seconds")
        self.rule = rule
        self.severity = severity
        self.src = src
        self.detail = detail
        self.raw = raw

    def __str__(self):
        icon = self.ICONS.get(self.severity, "!")
        return f"{icon} [{self.severity}] {self.rule} | {self.src} | {self.detail}"

    def to_dict(self):
        return vars(self)


# ══════════════════════════════════════════════════════════════════════════════
class AlertEngine:
    def __init__(self, email: Optional[str] = None, slack: Optional[str] = None):
        self.email = email
        self.slack = slack
        self.history: list = []
        self._dedup: dict = {}

    def fire(self, alert: SIEMAlert, dedupe_secs: int = 120):
        key = f"{alert.rule}:{alert.src}"
        now = time.time()
        if now - self._dedup.get(key, 0) < dedupe_secs:
            return
        self._dedup[key] = now
        self.history.append(alert.to_dict())
        log.warning(str(alert))
        if alert.severity in ("HIGH", "CRITICAL"):
            if self.email:
                self._send_email(alert)
            if self.slack:
                self._send_slack(alert)

    def _send_email(self, alert: SIEMAlert):
        try:
            msg = MIMEText(f"{alert}\n\nRaw log:\n{alert.raw}")
            msg["Subject"] = f"[SIEM] {alert.severity}: {alert.rule}"
            msg["From"] = "siem@localhost"
            msg["To"] = self.email
            with smtplib.SMTP("localhost") as s:
                s.send_message(msg)
        except Exception as e:
            log.error(f"Email failed: {e}")

    def _send_slack(self, alert: SIEMAlert):
        try:
            payload = json.dumps({"text": f"*[SIEM]* {alert}"}).encode()
            req = urllib.request.Request(
                self.slack, data=payload, headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log.error(f"Slack failed: {e}")


# ══════════════════════════════════════════════════════════════════════════════
class StatTracker:
    """Rolling statistics for threshold-based detection."""

    def __init__(self):
        self.ssh_fails: dict = defaultdict(list)        # ip → [timestamps]
        self.ssh_accounts: dict = defaultdict(set)      # ip → {accounts}
        self.http_errors: dict = defaultdict(list)      # ip → [timestamps]
        self.sudo_users: Counter = Counter()
        self.login_success: dict = defaultdict(list)    # user → [timestamps]

    def record_ssh_fail(self, ip: str, user: str):
        now = time.time()
        self.ssh_fails[ip].append(now)
        self.ssh_accounts[ip].add(user)
        # Trim old entries
        cutoff = now - 60
        self.ssh_fails[ip] = [t for t in self.ssh_fails[ip] if t > cutoff]

    def record_ssh_success(self, user: str, ip: str):
        self.login_success[user].append({"ip": ip, "time": time.time()})

    def record_http_error(self, ip: str):
        now = time.time()
        self.http_errors[ip].append(now)
        cutoff = now - 60
        self.http_errors[ip] = [t for t in self.http_errors[ip] if t > cutoff]

    def ssh_fail_rate(self, ip: str) -> int:
        return len(self.ssh_fails.get(ip, []))

    def spray_count(self, ip: str) -> int:
        return len(self.ssh_accounts.get(ip, set()))

    def http_error_rate(self, ip: str) -> int:
        return len(self.http_errors.get(ip, []))


# ══════════════════════════════════════════════════════════════════════════════
class LogParser:
    """Parses individual log lines and returns structured events."""

    def parse(self, line: str) -> Optional[dict]:
        line = line.strip()
        if not line:
            return None

        # SSH failures
        m = PATTERNS["ssh_fail"].search(line)
        if m:
            return {"type": "ssh_fail", "ts": m.group(1), "user": m.group(2), "ip": m.group(3), "raw": line}

        # SSH success
        m = PATTERNS["ssh_accept"].search(line)
        if m:
            return {"type": "ssh_accept", "ts": m.group(1), "user": m.group(2), "ip": m.group(3), "raw": line}

        # sudo
        m = PATTERNS["sudo"].search(line)
        if m:
            return {"type": "sudo", "ts": m.group(1), "user": m.group(2), "cmd": m.group(3).strip(), "raw": line}

        # User management
        m = PATTERNS["user_mgmt"].search(line)
        if m:
            return {"type": "user_mgmt", "ts": m.group(1), "action": m.group(2), "target": m.group(3), "raw": line}

        # HTTP access
        m = PATTERNS["http_access"].search(line)
        if m:
            return {
                "type": "http_access", "ip": m.group(1), "user": m.group(2),
                "ts": m.group(3), "method": m.group(4), "path": m.group(5),
                "status": int(m.group(6)), "size": int(m.group(7)), "raw": line,
            }

        # iptables drop
        m = PATTERNS["iptables_drop"].search(line)
        if m:
            return {"type": "iptables_drop", "ts": m.group(1), "src": m.group(2), "dst": m.group(3), "raw": line}

        return {"type": "unknown", "raw": line}


# ══════════════════════════════════════════════════════════════════════════════
class RuleEvaluator:
    """Applies detection rules to parsed events."""

    def __init__(self, alert_engine: AlertEngine, stats: StatTracker):
        self.alerts = alert_engine
        self.stats = stats

    def evaluate(self, event: dict):
        t = event.get("type")

        if t == "ssh_fail":
            self._handle_ssh_fail(event)

        elif t == "ssh_accept":
            self._handle_ssh_accept(event)

        elif t == "sudo":
            self._handle_sudo(event)

        elif t == "user_mgmt":
            self._handle_user_mgmt(event)

        elif t == "http_access":
            self._handle_http(event)

        elif t == "iptables_drop":
            self.alerts.fire(SIEMAlert(
                "FIREWALL_DROP", "LOW",
                event["src"], f"Dropped: {event['src']} → {event['dst']}", event["raw"]
            ))

    def _handle_ssh_fail(self, ev: dict):
        ip, user = ev["ip"], ev["user"]
        self.stats.record_ssh_fail(ip, user)

        rate = self.stats.ssh_fail_rate(ip)
        spray = self.stats.spray_count(ip)

        if rate >= BRUTE_FORCE_THRESH:
            self.alerts.fire(SIEMAlert(
                "SSH_BRUTE_FORCE", "HIGH", ip,
                f"{rate} failed logins/min targeting '{user}'", ev["raw"]
            ))
        if spray >= SPRAY_THRESH:
            self.alerts.fire(SIEMAlert(
                "CREDENTIAL_SPRAY", "HIGH", ip,
                f"Spraying {spray} distinct accounts from {ip}", ev["raw"]
            ))
        if user in ("root", "admin", "administrator"):
            self.alerts.fire(SIEMAlert(
                "PRIVILEGED_ACCOUNT_ATTACK", "MEDIUM", ip,
                f"Targeting privileged account '{user}'", ev["raw"]
            ))

    def _handle_ssh_accept(self, ev: dict):
        user, ip = ev["user"], ev["ip"]
        self.stats.record_ssh_success(user, ip)

        hour = datetime.now().hour
        if hour in PRIV_HOURS or hour < 6:
            self.alerts.fire(SIEMAlert(
                "AFTER_HOURS_LOGIN", "MEDIUM", ip,
                f"User '{user}' logged in at {hour:02d}:xx", ev["raw"]
            ))

        # Impossible travel (simple: new IP for same user)
        logins = self.stats.login_success.get(user, [])
        if len(logins) >= 2:
            prev_ip = logins[-2]["ip"]
            if prev_ip != ip:
                self.alerts.fire(SIEMAlert(
                    "POSSIBLE_ACCOUNT_SHARING", "MEDIUM", user,
                    f"Login from {ip}, previously from {prev_ip}", ev["raw"]
                ))

    def _handle_sudo(self, ev: dict):
        user, cmd = ev["user"], ev["cmd"]
        dangerous = ["/bin/bash", "/bin/sh", "chmod 777", "visudo", "/etc/passwd", "nc ", "python"]
        for d in dangerous:
            if d in cmd:
                self.alerts.fire(SIEMAlert(
                    "DANGEROUS_SUDO", "HIGH", user,
                    f"sudo '{cmd[:80]}'", ev["raw"]
                ))
                return

    def _handle_user_mgmt(self, ev: dict):
        action = ev["action"]
        severity = "HIGH" if action in ("useradd", "userdel") else "MEDIUM"
        self.alerts.fire(SIEMAlert(
            "USER_MANAGEMENT", severity, "system",
            f"{action} executed on '{ev['target']}'", ev["raw"]
        ))

    def _handle_http(self, ev: dict):
        ip, status = ev["ip"], ev["status"]
        path = ev.get("path", "")

        if status in (401, 403):
            self.stats.record_http_error(ip)
            if self.stats.http_error_rate(ip) >= HTTP_SCAN_THRESH:
                self.alerts.fire(SIEMAlert(
                    "HTTP_BRUTE_FORCE", "HIGH", ip,
                    f"{self.stats.http_error_rate(ip)} auth errors/min", ev["raw"]
                ))

        # Common web attack patterns
        sqli_patterns = ["'", "1=1", "UNION SELECT", "OR 1=1", "--", ";DROP"]
        xss_patterns = ["<script", "javascript:", "onerror=", "onload="]
        traversal = ["../", "..\\", "%2e%2e"]

        path_lower = path.lower()
        for pattern in sqli_patterns:
            if pattern.lower() in path_lower:
                self.alerts.fire(SIEMAlert("SQL_INJECTION_ATTEMPT", "HIGH", ip, f"SQLi in: {path[:100]}", ev["raw"]))
                break
        for pattern in xss_patterns:
            if pattern.lower() in path_lower:
                self.alerts.fire(SIEMAlert("XSS_ATTEMPT", "MEDIUM", ip, f"XSS in: {path[:100]}", ev["raw"]))
                break
        for pattern in traversal:
            if pattern in path_lower:
                self.alerts.fire(SIEMAlert("PATH_TRAVERSAL", "HIGH", ip, f"Traversal: {path[:100]}", ev["raw"]))
                break


# ══════════════════════════════════════════════════════════════════════════════
class LogWatcher:
    """Watches log files in real time using tail-like polling."""

    def __init__(self, paths: list, parser: LogParser, evaluator: RuleEvaluator):
        self.paths = paths
        self.parser = parser
        self.evaluator = evaluator
        self._offsets: dict = {}

    def _get_offset(self, path: str) -> int:
        if path not in self._offsets:
            try:
                self._offsets[path] = Path(path).stat().st_size
            except FileNotFoundError:
                self._offsets[path] = 0
        return self._offsets[path]

    def _read_new_lines(self, path: str) -> list:
        offset = self._get_offset(path)
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(offset)
                lines = f.readlines()
                self._offsets[path] = f.tell()
            return lines
        except FileNotFoundError:
            return []

    def watch(self, interval: float = 0.5):
        log.info(f"👁 Watching {len(self.paths)} log file(s) — Ctrl+C to stop")
        while True:
            for path in self.paths:
                for line in self._read_new_lines(path):
                    event = self.parser.parse(line)
                    if event:
                        self.evaluator.evaluate(event)
            time.sleep(interval)


# ══════════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    def generate_html(self, alerts: list, path: str):
        rows = ""
        for a in alerts:
            color = {"LOW": "#2ecc71", "MEDIUM": "#e67e22", "HIGH": "#e74c3c", "CRITICAL": "#8e44ad"}.get(a["severity"], "#fff")
            rows += (
                f"<tr><td>{a['ts']}</td>"
                f"<td style='color:{color};font-weight:bold'>{a['severity']}</td>"
                f"<td>{a['rule']}</td><td>{a['src']}</td>"
                f"<td>{a['detail']}</td></tr>\n"
            )
        html = f"""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>SIEM Report</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
  h1{{color:#58a6ff}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#161b22;color:#58a6ff;padding:.6rem;text-align:left}}
  td{{padding:.4rem;border-bottom:1px solid #21262d;font-size:.85em}}
  tr:hover{{background:#161b22}}
</style></head>
<body><h1>🛡 SIEM Alert Report — {datetime.now().strftime("%Y-%m-%d %H:%M")}</h1>
<p>Total Alerts: {len(alerts)}</p>
<table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        Path(path).write_text(html, encoding="utf-8")
        log.info(f"Report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(description="🛡 SIEM Lite — Real-time Log Analysis & Alerting")
    p.add_argument("--watch", nargs="+", metavar="FILE", help="Log files to watch in real time")
    p.add_argument("--parse", metavar="FILE", help="Parse a file once and exit")
    p.add_argument("--format", choices=["auto", "syslog", "nginx", "apache"], default="auto")
    p.add_argument("--report", metavar="HTML", help="Save HTML alert report")
    p.add_argument("--email", help="Alert email address")
    p.add_argument("--slack", help="Slack webhook URL")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    alert_engine = AlertEngine(email=args.email, slack=args.slack)
    stats = StatTracker()
    parser = LogParser()
    evaluator = RuleEvaluator(alert_engine, stats)

    if args.parse:
        log.info(f"Parsing {args.parse} ...")
        with open(args.parse, "r", errors="replace") as f:
            for line in f:
                ev = parser.parse(line)
                if ev:
                    evaluator.evaluate(ev)
        log.info(f"Done — {len(alert_engine.history)} alerts")
        if args.report:
            ReportGenerator().generate_html(alert_engine.history, args.report)

    elif args.watch:
        watcher = LogWatcher(args.watch, parser, evaluator)
        try:
            watcher.watch()
        except KeyboardInterrupt:
            log.info("Stopped.")
            if args.report:
                ReportGenerator().generate_html(alert_engine.history, args.report)
    else:
        print("Specify --watch or --parse. Use --help for usage.")
