import os
import time
from urllib.parse import urlparse

import requests

class URLScanTool:
    SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
    RESULT_URL = "https://urlscan.io/api/v1/result/"

    POLL_INTERVAL = 5
    MAX_WAIT = 120
    INITIAL_WAIT = 30

    def __init__(self, visibility="private"):
        if visibility not in {"public", "unlisted", "private"}:
            raise ValueError(
                "Visibility must be public, unlisted, or private"
            )

        self.visibility = visibility
        self.api_key = os.getenv("URLSCAN_API_KEY")

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        if not self.api_key:
            raise RuntimeError(
                "URLSCAN_API_KEY is not configured"
            )

        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "Theseus/0.5.0",
        }

        response = requests.post(
            self.SUBMIT_URL,
            headers=headers,
            json={
                "url": url,
                "visibility": self.visibility,
            },
            timeout=30,
        )
        response.raise_for_status()

        submission = response.json()
        scan_id = submission.get("uuid")

        if not scan_id:
            raise RuntimeError(
                f"urlscan.io did not return a scan UUID: {submission}"
            )

        result_url = f"{self.RESULT_URL}{scan_id}/"

        # Give the remote scanner time to finish its initial analysis.
        time.sleep(self.INITIAL_WAIT)

        elapsed = self.INITIAL_WAIT

        while elapsed <= self.MAX_WAIT:
            result_response = requests.get(
                result_url,
                headers=headers,
                timeout=15,
            )

            if result_response.status_code == 200:
                return {
                    "submitted_url": url,
                    "visibility": submission.get(
                        "visibility", self.visibility
                    ),
                    "scan_id": scan_id,
                    "result_url": submission.get(
                        "result",
                        f"https://urlscan.io/result/{scan_id}/",
                    ),
                    "submission": submission,
                    "raw_result": result_response.json(),
                }

            if result_response.status_code == 404:
                time.sleep(self.POLL_INTERVAL)
                elapsed += self.POLL_INTERVAL
                continue

            result_response.raise_for_status()

        return {
            "submitted_url": url,
            "visibility": submission.get(
                "visibility", self.visibility
            ),
            "scan_id": scan_id,
            "result_url": submission.get(
                "result",
                f"https://urlscan.io/result/{scan_id}/",
            ),
            "submission": submission,
            "raw_result": None,
            "status": "pending",
            "message": "Scan result was not ready before timeout",
        }