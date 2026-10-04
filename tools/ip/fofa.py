import os
import base64

import requests

class FOFATool:
    BASE_URL = "https://fofa.info/api/v1/search/all"

    def __init__(self) -> None:
        self.api_key = os.getenv("FOFA_API_KEY")

        if not self.api_key:
            raise ValueError("FOFA_API_KEY is not set")

    def run(self, ip: str) -> dict:
        query = f'ip="{ip}"'
        qbase64 = base64.b64encode(
            query.encode()
        ).decode()

        params = {
            "key": self.api_key,
            "qbase64": qbase64,
            "size": 100,
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()