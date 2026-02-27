"""
Threat Detection Engine - real log parsing + simulation mode
"""
import re
import random
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from config import (
    IS_SIMULATION, AUTH_LOG_PATH, NGINX_ACCESS_LOG, APACHE_ACCESS_LOG,
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW,
    DDOS_THRESHOLD, AUTO_BLOCK, SIMULATION_INTERVAL, ATTACK_TYPES,
    SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
)
from logger import logger
import database as db
from firewall import firewall

# ─── Simulation data ──────────────────────────────────────────────────────────
FAKE_IPS = [
    "192.168.1." + str(i) for i in range(1, 20)
] + [
    f"{a}.{b}.{c}.{d}"
    for a, b, c, d in [
        (45, 33, 178, 12), (103, 21, 194, 200), (185, 220, 101, 47),
        (91, 108, 4, 128), (77, 88, 55, 66), (123, 45, 67, 89),
        (198, 51, 100, 23), (203, 0, 113, 5), (222, 111, 33, 44),
        (8, 8, 8, 8), (1, 1, 1, 1), (66, 249, 73, 139),
    ]
]

FAKE_COUNTRIES = [
    "China 🇨🇳", "Russia 🇷🇺", "Iran 🇮🇷", "North Korea 🇰🇵",
    "Brazil 🇧🇷", "Vietnam 🇻🇳", "India 🇮🇳", "USA 🇺🇸",
    "Germany 🇩🇪", "Netherlands 🇳🇱", "Unknown 🌐",
]

SIM_ATTACK_POOL = [
    ("BRUTE_FORCE_SSH", "Multiple failed SSH login attempts", SEVERITY_HIGH),
    ("BRUTE_FORCE_FTP", "Repeated FTP authentication failures", SEVERITY_HIGH),
    ("PORT_SCAN", "Sequential port scanning detected", SEVERITY_MEDIUM),
    ("DDOS", "Abnormal traffic volume detected", SEVERITY_CRITICAL),
    ("SYN_FLOOD", "SYN packet flood detected", SEVERITY_CRITICAL),
    ("SQL_INJECTION", "SQL injection pattern in request", SEVERITY_HIGH),
    ("XSS", "Cross-site scripting payload detected", SEVERITY_MEDIUM),
    ("PATH_TRAVERSAL", "Directory traversal attempt", SEVERITY_HIGH),
    ("RCE_ATTEMPT", "Remote code execution attempt", SEVERITY_CRITICAL),
    ("SUSPICIOUS_UA", "Suspicious scanner user-agent detected", SEVERITY_LOW),
]

# ─── Real detection patterns ───────────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"(union.*select|select.*from|insert.*into|drop.*table|exec\(|"
    r"xp_cmdshell|1=1|'.*or.*'|--\s|/\*.*\*/|char\(\d+\))",
    re.IGNORECASE
)
XSS_PATTERNS = re.compile(
    r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie|"
    r"eval\(|<iframe|<img.*onerror)",
    re.IGNORECASE
)
PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e)", re.IGNORECASE)
RCE_PATTERNS = re.compile(
    r"(;.*wget|;.*curl|`.*`|\$\(.*\)|cmd\.exe|/bin/sh|/bin/bash|nc\s+-)",
    re.IGNORECASE
)


class ThreatDetector:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self._running = False
        self._thread = None
        # For real detection: track failed attempts per IP
        self._failed_attempts = defaultdict(deque)  # ip -> deque of timestamps
        self._port_access = defaultdict(deque)       # ip -> deque of (timestamp, port)
        self._connection_count = defaultdict(int)    # ip -> count per second

    def set_socketio(self, socketio):
        self.socketio = socketio

    def start(self):
        self._running = True
        if IS_SIMULATION:
            self._thread = threading.Thread(target=self._simulation_loop, daemon=True)
            logger.info("ThreatDetector: Starting in SIMULATION mode")
        else:
            self._thread = threading.Thread(target=self._real_detection_loop, daemon=True)
            logger.info("ThreatDetector: Starting in LIVE detection mode")
        self._thread.start()

    def stop(self):
        self._running = False

    # ── Simulation Loop ──────────────────────────────────────────────────────
    def _simulation_loop(self):
        time.sleep(2)  # Initial delay
        while self._running:
            # Generate 1-3 random attack events
            n = random.randint(1, 3)
            for _ in range(n):
                attack_type, details, severity = random.choice(SIM_ATTACK_POOL)
                ip = random.choice(FAKE_IPS)
                country = random.choice(FAKE_COUNTRIES)
                self._handle_threat(ip, country, attack_type, details, severity)
                time.sleep(random.uniform(0.2, 1.0))
            time.sleep(SIMULATION_INTERVAL)

    # ── Real Detection Loop (Linux) ───────────────────────────────────────────
    def _real_detection_loop(self):
        log_position = self._get_log_size()
        while self._running:
            try:
                self._scan_auth_log(log_position)
                self._scan_web_logs()
                self._check_network_anomalies()
            except Exception as e:
                logger.error(f"Detection error: {e}")
            time.sleep(3)

    def _get_log_size(self):
        try:
            return os.path.getsize(AUTH_LOG_PATH)
        except Exception:
            return 0

    def _scan_auth_log(self, start_pos=0):
        import os
        try:
            with open(AUTH_LOG_PATH, "r", errors="ignore") as f:
                f.seek(start_pos)
                for line in f:
                    if "Failed password" in line or "Invalid user" in line:
                        ip = self._extract_ip(line)
                        if ip:
                            self._record_failed_attempt(ip, "SSH")
        except FileNotFoundError:
            pass

    def _scan_web_logs(self):
        for log_path in [NGINX_ACCESS_LOG, APACHE_ACCESS_LOG]:
            try:
                with open(log_path, "r", errors="ignore") as f:
                    for line in f:
                        ip = self._extract_ip(line)
                        if not ip:
                            continue
                        if SQLI_PATTERNS.search(line):
                            self._handle_threat(ip, "Unknown", "SQL_INJECTION",
                                                "SQL injection pattern in request", SEVERITY_HIGH)
                        elif XSS_PATTERNS.search(line):
                            self._handle_threat(ip, "Unknown", "XSS",
                                                "XSS payload detected", SEVERITY_MEDIUM)
                        elif PATH_TRAVERSAL.search(line):
                            self._handle_threat(ip, "Unknown", "PATH_TRAVERSAL",
                                                "Path traversal attempt", SEVERITY_HIGH)
                        elif RCE_PATTERNS.search(line):
                            self._handle_threat(ip, "Unknown", "RCE_ATTEMPT",
                                                "RCE attempt detected", SEVERITY_CRITICAL)
            except FileNotFoundError:
                pass

    def _check_network_anomalies(self):
        try:
            import psutil
            conns = psutil.net_connections(kind="inet")
            ip_counts = defaultdict(int)
            for conn in conns:
                if conn.raddr:
                    ip_counts[conn.raddr.ip] += 1
            for ip, count in ip_counts.items():
                if count > DDOS_THRESHOLD and ip not in ["127.0.0.1", "::1"]:
                    self._handle_threat(ip, "Unknown", "DDOS",
                                        f"{count} active connections from single IP", SEVERITY_CRITICAL)
        except Exception:
            pass

    def _record_failed_attempt(self, ip, service):
        now = time.time()
        dq = self._failed_attempts[ip]
        dq.append(now)
        # Remove old entries
        while dq and now - dq[0] > BRUTE_FORCE_WINDOW:
            dq.popleft()
        if len(dq) >= BRUTE_FORCE_THRESHOLD:
            attack_type = f"BRUTE_FORCE_{service}"
            self._handle_threat(ip, "Unknown", attack_type,
                                f"{len(dq)} failed {service} attempts in {BRUTE_FORCE_WINDOW}s",
                                SEVERITY_HIGH)
            dq.clear()  # Reset after alerting

    def _extract_ip(self, line):
        match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        return match.group(1) if match else None

    def _get_country(self, ip):
        """Geolocation via free API (cached)"""
        try:
            import requests
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode",
                                timeout=2)
            data = resp.json()
            return data.get("country", "Unknown")
        except Exception:
            return "Unknown"

    # ── Core handler ─────────────────────────────────────────────────────────
    def _handle_threat(self, ip, country, attack_type, details, severity):
        attack_info = ATTACK_TYPES.get(attack_type, {"name": attack_type})
        attack_name = attack_info.get("name", attack_type)

        action = "DETECTED"
        if AUTO_BLOCK and severity in [SEVERITY_HIGH, SEVERITY_CRITICAL]:
            if not db.is_ip_blocked(ip):
                firewall.block_ip(ip)
                db.block_ip(ip, reason=attack_name)
                action = "BLOCKED"

        # Save to DB
        event_id = db.insert_event(ip, country, attack_type, attack_name, severity, details, action)

        # Emit via WebSocket
        event_data = {
            "id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "country": country,
            "attack_type": attack_type,
            "attack_name": attack_name,
            "severity": severity,
            "details": details,
            "action": action,
        }

        if self.socketio:
            self.socketio.emit("threat_event", event_data)

        log_msg = f"[{severity}] {attack_name} from {ip} ({country}) → {action}"
        if severity == SEVERITY_CRITICAL:
            logger.critical(log_msg)
        elif severity == SEVERITY_HIGH:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

        return event_data
