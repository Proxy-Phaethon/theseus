import requests

class IPAPIIsTool:
    BASE_URL = "https://api.ipapi.is"

    def run(self, ip: str) -> dict:
        params = {
            "q": ip,
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()