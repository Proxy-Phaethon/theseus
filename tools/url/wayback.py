from urllib.parse import urlparse

import requests

class WaybackTool:
    API_URL = "https://web.archive.org/cdx/search/cdx"
    ARCHIVE_URL = "https://web.archive.org/web"

    FIELDS = [
        "timestamp",
        "original",
        "mimetype",
        "statuscode",
        "digest",
        "length",
    ]

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        response = requests.get(
            self.API_URL,
            params={
                "url": url,
                "output": "json",
                "fl": ",".join(self.FIELDS),
                "filter": "statuscode:200",
                "collapse": "digest",
                "limit": 100,
            },
            headers={"User-Agent": "Theseus/0.5.0"},
            timeout=45,
        )
        response.raise_for_status()

        raw_result = response.json()

        if not raw_result:
            headers = []
            rows = []
        else:
            headers = raw_result[0]
            rows = raw_result[1:]

        captures = [
            dict(zip(headers, row))
            for row in rows
            if len(row) == len(headers)
        ]

        for capture in captures:
            timestamp = capture.get("timestamp")
            capture["archive_url"] = (
                f"{self.ARCHIVE_URL}/{timestamp}/{capture['original']}"
                if timestamp and capture.get("original")
                else None
            )

        return {
            "requested_url": url,
            "status": "found" if captures else "not_found",
            "capture_count": len(captures),
            "captures": captures,
            "raw_result": raw_result,
        }