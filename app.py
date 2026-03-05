"""
Flask + SocketIO web server - API endpoints and real-time broadcast
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import database as db
from firewall import firewall
from monitor import SystemMonitor
from threat_detector import ThreatDetector
from tarpit import tarpit
from logger import logger
from config import APP_HOST, APP_PORT, APP_SECRET_KEY, ENABLE_WEB_HONEYPOT, SEVERITY_HIGH

app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize components
monitor = SystemMonitor()
detector = ThreatDetector()

# ─── WebSocket Events ──────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.info(f"Dashboard client connected: {request.sid}")
    # Send initial snapshot on connect
    emit("initial_data", {
        "events":      db.get_recent_events(50),
        "blocked_ips": db.get_blocked_ips(),
        "stats":       db.get_stats_summary(),
    })

@socketio.on("disconnect")
def on_disconnect():
    logger.info(f"Dashboard client disconnected: {request.sid}")

# ─── REST API ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", 100, type=int)
    return jsonify(db.get_recent_events(limit))


@app.route("/api/blocked-ips")
def api_blocked_ips():
    return jsonify(db.get_blocked_ips())


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats_summary())


@app.route("/api/metrics")
def api_metrics():
    return jsonify(monitor.get_metrics())


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP is required"}), 400
    firewall.unblock_ip(ip)
    db.unblock_ip(ip)
    socketio.emit("ip_unblocked", {"ip": ip})
    logger.info(f"API: Manually unblocked {ip}")
    return jsonify({"success": True, "ip": ip})


@app.route("/api/clear-events", methods=["POST"])
def api_clear_events():
    import sqlite3
    conn = db.get_connection()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    socketio.emit("events_cleared", {})
    return jsonify({"success": True})


# ─── Web Honeypot (Zip Bomb) ───────────────────────────────────────────────────
# Rute-rute yang sering dicari bot (vulnerability scanner)
HONEYPOT_ROUTES = [
    "/wp-login.php", "/wp-admin", "/.env", "/phpmyadmin", "/mysql", "/sql",
    "/admin", "/login.php", "/config.php", "/backup.zip", "/archive.zip"
]

@app.route("/<path:req_path>")
def catch_all(req_path):
    # Jika honeypot aktif dan dicari rute berbahaya
    if ENABLE_WEB_HONEYPOT and ("/" + req_path in HONEYPOT_ROUTES or req_path.endswith(".php") or ".env" in req_path):
        ip = request.headers.get("X-Real-IP", request.remote_addr)
        
        # Log ancaman
        import datetime
        country = detector._get_country(ip) if hasattr(detector, '_get_country') else "Unknown"
        action = "HONEYPOT"
        
        event_id = db.insert_event(
            ip, country, "HONEYPOT_CAUGHT", "Caught in Web Honeypot", 
            SEVERITY_HIGH, f"Bot scanned for /{req_path}, returning GZIP Bomb", action
        )
        
        event_data = {
            "id": event_id,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip, "country": country, "attack_type": "HONEYPOT_CAUGHT",
            "attack_name": "Caught in Web Honeypot", "severity": SEVERITY_HIGH,
            "details": f"Hit /{req_path}", "action": action
        }
        socketio.emit("threat_event", event_data)
        logger.warning(f"Web Honeypot: Bot {ip} tried to access /{req_path} -> Sending GZIP Bomb")
        
        # Kirim Gzip Bomb (Payload 10MB byte nol terekompresi)
        # Akan menguras memori bot yang mencoba mengekstraknya otomatis
        import gzip
        import io
        
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(b"0" * 10_000_000)  # 10 MB of zeros, compresses very small
            
        from flask import make_response
        response = make_response(out.getvalue())
        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Content-Length'] = str(len(out.getvalue()))
        response.headers['Content-Type'] = 'text/html'
        
        # Block sekalian jika auto-block nyala di firewall
        from config import AUTO_BLOCK
        if AUTO_BLOCK and not db.is_ip_blocked(ip):
            firewall.block_ip(ip)
            db.block_ip(ip, reason="Web Honeypot Trap")
            
        return response, 200

    # Normal 404
    return "Not Found", 404


# ─── App startup ──────────────────────────────────────────────────────────────
def start_background_services():
    monitor.set_socketio(socketio)
    detector.set_socketio(socketio)
    tarpit.socketio = socketio
    
    monitor.start()
    detector.start()
    tarpit.start()
    
    logger.info("Background services started")


if __name__ == "__main__":
    db.init_db()
    start_background_services()
    logger.info(f"VPS Sentinel starting on http://{APP_HOST}:{APP_PORT}")
    socketio.run(app, host=APP_HOST, port=APP_PORT, debug=False, allow_unsafe_werkzeug=True)
