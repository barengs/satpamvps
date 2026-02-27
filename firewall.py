"""
Firewall integration module - iptables wrapper with simulation mode
"""
import subprocess
from config import IS_LINUX, WHITELIST_IPS
from logger import logger


class FirewallManager:
    def __init__(self):
        self.simulation_mode = not IS_LINUX
        self._sim_blocked = set()  # Simulated blocked IPs on Windows
        if self.simulation_mode:
            logger.info("FirewallManager: Running in SIMULATION mode (no real iptables)")
        else:
            logger.info("FirewallManager: Running in LIVE mode (iptables active)")

    def block_ip(self, ip: str) -> bool:
        """Block an IP address via iptables (or simulate it)."""
        if ip in WHITELIST_IPS:
            logger.warning(f"Firewall: Skipped blocking whitelisted IP {ip}")
            return False

        if self.simulation_mode:
            self._sim_blocked.add(ip)
            logger.info(f"[SIM] Firewall: BLOCKED {ip}")
            return True

        try:
            # Check if rule already exists
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode == 0:
                return True  # Already blocked

            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info(f"Firewall: BLOCKED {ip} via iptables")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall: Failed to block {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove IP block from iptables."""
        if self.simulation_mode:
            self._sim_blocked.discard(ip)
            logger.info(f"[SIM] Firewall: UNBLOCKED {ip}")
            return True

        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            logger.info(f"Firewall: UNBLOCKED {ip}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Firewall: Failed to unblock {ip}: {e}")
            return False

    def get_blocked_ips(self) -> list:
        """Get list of currently blocked IPs."""
        if self.simulation_mode:
            return list(self._sim_blocked)

        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n", "--line-numbers"],
                capture_output=True, text=True, check=True
            )
            blocked = []
            for line in result.stdout.splitlines():
                if "DROP" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        blocked.append(parts[3])
            return blocked
        except Exception as e:
            logger.error(f"Firewall: Failed to list blocked IPs: {e}")
            return []

    def is_blocked(self, ip: str) -> bool:
        if self.simulation_mode:
            return ip in self._sim_blocked
        return ip in self.get_blocked_ips()


# Singleton
firewall = FirewallManager()
