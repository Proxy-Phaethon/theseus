import requests

class TorExitListTool:
    BASE_URL = "https://check.torproject.org/torbulkexitlist"

    def run(self, ip: str) -> dict:
        response = requests.get(
            self.BASE_URL,
            timeout=15,
        )
        response.raise_for_status()

        exit_ips = {
            line.strip()
            for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        }

        return {
            "ip": ip,
            "is_tor_exit": ip in exit_ips,
        }