import requests
from urllib.parse import quote

class XposedOrNotTool:
    BASE_URL = "https://api.xposedornot.com"

    def run(self, email):
        url = f"{self.BASE_URL}/v1/check-email/{quote(email, safe='')}"

        response = requests.get(
            url,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()