"""
VPS Sentinel — Main entry point
"""
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db
from logger import logger
from config import APP_HOST, APP_PORT, IS_SIMULATION

def main():
    logger.info("=" * 55)
    logger.info("  VPS Sentinel — Cyber Attack Prevention System")
    logger.info(f"  Mode: {'SIMULATION (Windows)' if IS_SIMULATION else 'LIVE (Linux)'}")
    logger.info("=" * 55)

    # Initialize database
    logger.info("Initializing database...")
    db.init_db()

    # Import and start Flask app
    from app import app, socketio, start_background_services
    start_background_services()

    logger.info(f"Dashboard berjalan di: http://localhost:{APP_PORT}")
    logger.info("Tekan Ctrl+C untuk menghentikan\n")

    socketio.run(app, host=APP_HOST, port=APP_PORT, debug=False, allow_unsafe_werkzeug=True)

if __name__ == "__main__":
    main()
