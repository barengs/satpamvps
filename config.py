"""
Configuration settings for VPS Attack Prevention & Monitoring System
"""
import os
import platform
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ─── System Detection ──────────────────────────────────────────────────────────
IS_LINUX = platform.system() == "Linux"
IS_SIMULATION = not IS_LINUX  # Simulation mode on Windows/Mac

# ─── Application ───────────────────────────────────────────────────────────────
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "5000"))
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "vps-sentinel-secret-2026")
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() in ["true", "1", "yes"]

# ─── Database ──────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "data", "sentinel.db")

# ─── Log Files (Linux only) ────────────────────────────────────────────────────
AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"
APACHE_ACCESS_LOG = "/var/log/apache2/access.log"

# ─── Threat Detection Thresholds ───────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # Failed attempts before blocking
BRUTE_FORCE_WINDOW = 60         # Time window in seconds
PORT_SCAN_THRESHOLD = 10        # Unique ports in time window
PORT_SCAN_WINDOW = 30           # Time window in seconds
DDOS_THRESHOLD = 100            # Connections per second per IP
SYN_FLOOD_THRESHOLD = 50        # SYN packets per second

# ─── Firewall ──────────────────────────────────────────────────────────────────
AUTO_BLOCK = True               # Automatically block detected IPs
BLOCK_DURATION = 3600           # Block duration in seconds (1 hour), 0 = permanent
WHITELIST_IPS = [               # These IPs will never be blocked
    "127.0.0.1",
    "::1",
]

# ─── Monitoring Intervals ──────────────────────────────────────────────────────
SYSTEM_MONITOR_INTERVAL = 2     # Seconds between system metric updates
THREAT_SCAN_INTERVAL = 3        # Seconds between threat scans
SIMULATION_INTERVAL = 4         # Seconds between simulated attack events

# ─── Severity Levels ───────────────────────────────────────────────────────────
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_COLORS = {
    SEVERITY_LOW: "#4CAF50",
    SEVERITY_MEDIUM: "#FF9800",
    SEVERITY_HIGH: "#F44336",
    SEVERITY_CRITICAL: "#9C27B0",
}

# ─── Attack Types ──────────────────────────────────────────────────────────────
ATTACK_TYPES = {
    "BRUTE_FORCE_SSH": {"name": "SSH Brute Force", "severity": SEVERITY_HIGH},
    "BRUTE_FORCE_FTP": {"name": "FTP Brute Force", "severity": SEVERITY_HIGH},
    "PORT_SCAN": {"name": "Port Scanning", "severity": SEVERITY_MEDIUM},
    "DDOS": {"name": "DDoS Attack", "severity": SEVERITY_CRITICAL},
    "SYN_FLOOD": {"name": "SYN Flood", "severity": SEVERITY_CRITICAL},
    "SQL_INJECTION": {"name": "SQL Injection", "severity": SEVERITY_HIGH},
    "XSS": {"name": "Cross-Site Scripting", "severity": SEVERITY_MEDIUM},
    "PATH_TRAVERSAL": {"name": "Path Traversal", "severity": SEVERITY_HIGH},
    "RCE_ATTEMPT": {"name": "Remote Code Execution", "severity": SEVERITY_CRITICAL},
    "SUSPICIOUS_UA": {"name": "Suspicious User Agent", "severity": SEVERITY_LOW},
    "TARPIT_CAUGHT": {"name": "Caught in SSH Tarpit", "severity": SEVERITY_MEDIUM},
    "HONEYPOT_CAUGHT": {"name": "Caught in Web Honeypot", "severity": SEVERITY_HIGH},
}

# ─── Countermeasures (Defense) ─────────────────────────────────────────────────
ENABLE_SSH_TARPIT = os.getenv("ENABLE_SSH_TARPIT", "True").lower() in ["true", "1", "yes"]
SSH_TARPIT_PORT = int(os.getenv("SSH_TARPIT_PORT", "2222"))
SSH_TARPIT_DELAY = float(os.getenv("SSH_TARPIT_DELAY", "2.0"))

ENABLE_WEB_HONEYPOT = os.getenv("ENABLE_WEB_HONEYPOT", "True").lower() in ["true", "1", "yes"]

