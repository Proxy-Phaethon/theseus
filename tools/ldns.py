import requests

class LDNSTool:
    BASE_URL = "https://ldns.com"

    def run(self, domain):
        url = f"{self.BASE_URL}/{domain}"

        response = requests.get(
            url,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()