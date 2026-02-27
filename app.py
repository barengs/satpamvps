"""
Flask + SocketIO web server - API endpoints and real-time broadcast
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import database as db
from firewall import firewall
from monitor import SystemMonitor
from threat_detector import ThreatDetector
from logger import logger
from config import APP_HOST, APP_PORT, APP_SECRET_KEY

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


# ─── App startup ──────────────────────────────────────────────────────────────
def start_background_services():
    monitor.set_socketio(socketio)
    detector.set_socketio(socketio)
    monitor.start()
    detector.start()
    logger.info("Background services started")


if __name__ == "__main__":
    db.init_db()
    start_background_services()
    logger.info(f"VPS Sentinel starting on http://{APP_HOST}:{APP_PORT}")
    socketio.run(app, host=APP_HOST, port=APP_PORT, debug=False, allow_unsafe_werkzeug=True)
