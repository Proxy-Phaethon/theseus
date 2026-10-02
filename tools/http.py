import time

import requests

class HTTPTool:
    def run(self, url):
        start = time.perf_counter()

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True,
        )

        elapsed = time.perf_counter() - start

        return {
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": dict(response.headers),
            "content_type": response.headers.get("Content-Type"),
            "content_length": len(response.content),
            "response_time_ms": round(elapsed * 1000),
            "redirects": [
                {
                    "url": item.url,
                    "status_code": item.status_code,
                    "location": item.headers.get("Location"),
                }
                for item in response.history
            ],
        }