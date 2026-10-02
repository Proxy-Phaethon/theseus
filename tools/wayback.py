import requests
from urllib.parse import quote

class WaybackTool:
    BASE_URL = "https://web.archive.org/cdx/search/cdx"

    def run(self, url):
        params = {
            "url": url,
            "output": "json",
            "filter": "statuscode:200",
            "collapse": "digest",
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()