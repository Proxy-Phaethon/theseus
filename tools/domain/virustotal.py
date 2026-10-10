import os
import requests

class VirusTotalTool:
    def run(self, domain):
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not set")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()