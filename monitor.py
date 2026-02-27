"""
System resource monitor - CPU, RAM, network metrics via psutil
"""
import time
import threading
import psutil
from logger import logger
from config import SYSTEM_MONITOR_INTERVAL
import database as db


class SystemMonitor:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self._running = False
        self._thread = None
        self._prev_net = psutil.net_io_counters()

    def set_socketio(self, socketio):
        self.socketio = socketio

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("SystemMonitor: Started")

    def stop(self):
        self._running = False

    def get_metrics(self) -> dict:
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage("/") if hasattr(psutil, "disk_usage") else None
        net = psutil.net_io_counters()
        try:
            connections = len(psutil.net_connections(kind="inet"))
        except Exception:
            connections = 0

        net_in  = max(0, net.bytes_recv - self._prev_net.bytes_recv)
        net_out = max(0, net.bytes_sent - self._prev_net.bytes_sent)
        self._prev_net = net

        metrics = {
            "cpu_percent":        round(cpu, 1),
            "ram_percent":        round(ram.percent, 1),
            "ram_used_mb":        round(ram.used / 1024 / 1024, 1),
            "ram_total_mb":       round(ram.total / 1024 / 1024, 1),
            "disk_percent":       round(disk.percent, 1) if disk else 0,
            "net_in_kbps":        round(net_in / 1024 / SYSTEM_MONITOR_INTERVAL, 1),
            "net_out_kbps":       round(net_out / 1024 / SYSTEM_MONITOR_INTERVAL, 1),
            "active_connections": connections,
            "bytes_sent":         net.bytes_sent,
            "bytes_recv":         net.bytes_recv,
        }
        return metrics

    def _monitor_loop(self):
        while self._running:
            try:
                metrics = self.get_metrics()
                db.insert_system_stat(
                    metrics["cpu_percent"],
                    metrics["ram_percent"],
                    metrics["bytes_sent"],
                    metrics["bytes_recv"],
                    metrics["active_connections"],
                )
                if self.socketio:
                    self.socketio.emit("system_metrics", metrics)
            except Exception as e:
                logger.error(f"SystemMonitor error: {e}")
            time.sleep(SYSTEM_MONITOR_INTERVAL)
