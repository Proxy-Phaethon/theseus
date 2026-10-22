import os
from urllib.parse import urlparse

import requests

class URLhausTool:
    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self):
        self.auth_key = os.getenv("URLHAUS_AUTH_KEY")

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        if not self.auth_key:
            raise RuntimeError("URLHAUS_AUTH_KEY is not configured")

        response = requests.post(
            self.API_URL,
            data={"url": url},
            headers={"Auth-Key": self.auth_key},
            timeout=30,
        )
        response.raise_for_status()

        raw_result = response.json()
        query_status = raw_result.get("query_status", "unknown")

        if query_status == "ok":
            status = "found"
        elif query_status == "no_results":
            status = "not_found"
        else:
            status = "unknown"

        return {
            "requested_url": url,
            "status": status,
            "raw_result": raw_result,
        }