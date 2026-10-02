import requests
from urllib.parse import quote

class DisifyTool:
    BASE_URL = "https://disify.com/api"

    def run(self, email):
        url = f"{self.BASE_URL}/email/{quote(email, safe='')}"

        response = requests.get(
            url,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()