import os
import requests

class AlienVaultOTXTool:
    BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"

    def __init__(self) -> None:
        self.api_key = os.getenv("OTX_API_KEY")

        if not self.api_key:
            raise ValueError("OTX_API_KEY is not set")

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}/general"

        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()
        return response.json()