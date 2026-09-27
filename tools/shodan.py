import os
from urllib.parse import quote

import requests

class ShodanTool:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")

        if not self.api_key:
            raise ValueError("SHODAN_API_KEY is required")

    def search_ip(self, ip):
        url = f"{self.BASE_URL}/shodan/host/{quote(ip, safe='')}"

        response = requests.get(
            url,
            params={"key": self.api_key},
            timeout=10,
        )

        response.raise_for_status()

        return response.json()

    def search_domain(self, domain):
        url = f"{self.BASE_URL}/dns/domain/{quote(domain, safe='')}"

        response = requests.get(
            url,
            params={"key": self.api_key},
            timeout=10,
        )

        response.raise_for_status()

        return response.json()