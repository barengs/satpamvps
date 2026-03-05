"""
VPS Sentinel — Defensive Countermeasures
SSH Tarpit (Endless SSH) & Web Honeypot logic
"""
import socket
import threading
import time
import random
from logger import logger
from config import ENABLE_SSH_TARPIT, SSH_TARPIT_PORT, SSH_TARPIT_DELAY, SEVERITY_MEDIUM
import database as db


class SSHTarpit:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self.thread = None
        self.server_socket = None
        self.active_connections = 0

    def start(self):
        if not ENABLE_SSH_TARPIT:
            return

        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        logger.info(f"SSHTarpit: Started listening on port {SSH_TARPIT_PORT}")

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _listen_loop(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(("0.0.0.0", SSH_TARPIT_PORT))
            self.server_socket.listen(100)
        except Exception as e:
            logger.error(f"SSHTarpit: Failed to bind port {SSH_TARPIT_PORT}: {e}")
            return

        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                ip = addr[0]
                self.active_connections += 1
                logger.info(f"SSHTarpit: Bot caught! {ip} connected via port {SSH_TARPIT_PORT}")
                
                # Log event
                event_data = {
                    "ip": ip,
                    "country": self._get_country(ip),
                    "attack_type": "TARPIT_CAUGHT",
                    "attack_name": "Caught in SSH Tarpit",
                    "severity": SEVERITY_MEDIUM,
                    "details": f"Bot {ip} trapped in endless SSH loop",
                    "action": "TRAPPED",
                }
                self._record_event(event_data)
                
                # Handle connection in new thread
                threading.Thread(target=self._handle_client, args=(client_sock, ip), daemon=True).start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"SSHTarpit accept error: {e}")

    def _handle_client(self, client_sock, ip):
        try:
            # First send standard SSH header to trick the bot
            client_sock.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n")
            
            while self.running:
                # Send random garbage bytes very slowly
                # This keeps the connection alive and the bot hanging
                garbage = bytes([random.randint(32, 126)]) + b"\r\n"
                client_sock.sendall(garbage)
                time.sleep(SSH_TARPIT_DELAY)
        except Exception:
            # Client usually disconnects eventually when timeout hit
            pass
        finally:
            self.active_connections = max(0, self.active_connections - 1)
            try:
                client_sock.close()
            except Exception:
                pass
            logger.debug(f"SSHTarpit: Bot {ip} disconnected.")

    def _get_country(self, ip):
        try:
            import requests
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=2)
            return resp.json().get("country", "Unknown")
        except Exception:
            return "Unknown"

    def _record_event(self, data):
        import datetime
        event_id = db.insert_event(
            data["ip"], data["country"], data["attack_type"], 
            data["attack_name"], data["severity"], data["details"], data["action"]
        )
        data["id"] = event_id
        data["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.socketio:
            self.socketio.emit("threat_event", data)


# Shared instance
tarpit = SSHTarpit()
