import os

import requests

class CensysTool:
    BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"

    def __init__(self) -> None:
        self.api_token = os.getenv("CENSYS_API_TOKEN")

        if not self.api_token:
            raise ValueError("CENSYS_API_TOKEN is not set")

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}"

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()