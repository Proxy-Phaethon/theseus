import os
import requests

class VirusTotalTool:
    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

    def __init__(self) -> None:
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY is not set")

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}"

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()
        return response.json()