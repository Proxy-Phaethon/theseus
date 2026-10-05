import os

import requests

class IPInfoTool:
    BASE_URL = "https://ipinfo.io"

    def __init__(self) -> None:
        self.api_token = os.getenv("IPINFO_API_TOKEN")

        if not self.api_token:
            raise ValueError("IPINFO_API_TOKEN is not set")

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}/json"

        params = {
            "token": self.api_token,
        }

        response = requests.get(
            url,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()