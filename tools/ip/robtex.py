import requests

class RobtexTool:
    BASE_URL = "https://freeapi.robtex.com/ipquery"

    def run(self, ip: str) -> dict:
        url = f"{self.BASE_URL}/{ip}"

        response = requests.get(
            url,
            timeout=15,
        )

        response.raise_for_status()
        return response.json()