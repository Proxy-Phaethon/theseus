import base64
import os
from urllib.parse import urlparse

import requests

class VirusTotalTool:
    API_URL = "https://www.virustotal.com/api/v3/urls"

    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        if not self.api_key:
            raise RuntimeError(
                "VIRUSTOTAL_API_KEY is not configured"
            )

        # VirusTotal accepts URL-safe Base64 without padding.
        url_id = (
            base64.urlsafe_b64encode(url.encode("utf-8"))
            .decode("ascii")
            .rstrip("=")
        )

        response = requests.get(
            f"{self.API_URL}/{url_id}",
            headers={
                "x-apikey": self.api_key,
                "accept": "application/json",
            },
            timeout=30,
        )

        if response.status_code == 404:
            return {
                "requested_url": url,
                "status": "not_found",
                "http_status": response.status_code,
                "raw_result": response.json(),
            }

        response.raise_for_status()

        return {
            "requested_url": url,
            "status": "found",
            "http_status": response.status_code,
            "raw_result": response.json(),
        }