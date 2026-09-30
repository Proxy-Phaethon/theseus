import requests

class LDNSTool:
    BASE_URL = "https://ldns.com"

    def run(self, domain):
        response = requests.get(
            f"{self.BASE_URL}/api/server",
            params={"domain": domain},
            timeout=10,
        )

        response.raise_for_status()

        return response.json()