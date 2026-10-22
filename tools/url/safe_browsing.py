import os
from urllib.parse import urlparse

import requests

class SafeBrowsingTool:
    API_URL = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    def __init__(self):
        self.api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        if not self.api_key:
            raise RuntimeError(
                "GOOGLE_SAFE_BROWSING_API_KEY is not configured"
            )

        response = requests.post(
            self.API_URL,
            params={"key": self.api_key},
            json={
                "client": {
                    "clientId": "theseus",
                    "clientVersion": "0.5.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=30,
        )
        response.raise_for_status()

        raw_result = response.json()

        return {
            "requested_url": url,
            "status": (
                "match_found"
                if raw_result.get("matches")
                else "no_match"
            ),
            "raw_result": raw_result,
        }