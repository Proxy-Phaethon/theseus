import json
import time
from urllib.parse import urlparse

import requests

class CommonCrawlTool:
    COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"
    TIMEOUT = 45
    MAX_CAPTURES = 100
    RETRY_DELAYS = (5, 15)

    TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        hostname = parsed.hostname.lower().rstrip(".")
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        start = time.perf_counter()
        headers = {"User-Agent": "Theseus/0.5.0"}

        # Discover the latest available Common Crawl index.
        collections_response = requests.get(
            self.COLLECTIONS_URL,
            headers=headers,
            timeout=self.TIMEOUT,
        )
        collections_response.raise_for_status()
        collections = collections_response.json()

        if not isinstance(collections, list) or not collections:
            raise ValueError("No Common Crawl indexes were returned")

        collection = collections[0]
        index_id = collection.get("id")
        index_url = collection.get("cdx-api")

        if not index_id or not index_url:
            raise ValueError(
                "Latest Common Crawl index has no usable endpoint"
            )

        # Search for captures of the domain and its subdomains.
        params = {
            "url": domain,
            "matchType": "domain",
            "output": "json",
            "limit": self.MAX_CAPTURES,
        }

        raw_result = []

        for attempt in range(len(self.RETRY_DELAYS) + 1):
            try:
                response = requests.get(
                    index_url,
                    params=params,
                    headers=headers,
                    timeout=self.TIMEOUT,
                )

                if response.status_code == 404:
                    raw_result = []
                    break

                if response.status_code in self.TRANSIENT_STATUS_CODES:
                    if attempt < len(self.RETRY_DELAYS):
                        time.sleep(self.RETRY_DELAYS[attempt])
                        continue

                response.raise_for_status()

                raw_result = [
                    json.loads(line)
                    for line in response.text.splitlines()
                    if line.strip()
                ]
                break

            except requests.exceptions.RequestException:
                if attempt >= len(self.RETRY_DELAYS):
                    raise

                time.sleep(self.RETRY_DELAYS[attempt])

        return {
            "requested_url": url,
            "queried_domain": domain,
            "index_id": index_id,
            "index_name": collection.get("name"),
            "status": "found" if raw_result else "not_found",
            "capture_count": len(raw_result),
            "captures": raw_result,
            "elapsed_ms": round(
                (time.perf_counter() - start) * 1000
            ),
        }