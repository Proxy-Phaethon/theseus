import os

import requests

class NetlasTool:
    BASE_URL = "https://app.netlas.io/api/host"

    def __init__(self) -> None:
        self.api_key = os.getenv("NETLAS_API_KEY")

        if not self.api_key:
            raise ValueError("NETLAS_API_KEY is not set")

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}/"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()