import requests

class RIPEstatTool:
    BASE_URL = "https://stat.ripe.net/data/network-info/data.json"


    def run(self, ip: str) -> dict:
        params = {
            "resource": ip,
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()