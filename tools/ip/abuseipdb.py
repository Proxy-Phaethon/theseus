import os

import requests

class AbuseIPDBTool:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self) -> None:
        self.api_key = os.getenv("ABUSEIPDB_API_KEY")

        if not self.api_key:
            raise ValueError("ABUSEIPDB_API_KEY is not set")

    def run(self, ip: str) -> dict:
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }

        response = requests.get(
            self.BASE_URL,
            headers=headers,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()