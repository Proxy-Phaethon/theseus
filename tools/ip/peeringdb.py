import requests

class PeeringDBTool:
    BASE_URL = "https://www.peeringdb.com/api/net"

    def run(self, asn: int | str) -> dict:
        params = {
            "asn": asn,
        }

        response = requests.get(
            self.BASE_URL,
            params=params,
            headers={
                "Accept": "application/json",
            },
            timeout=15,
        )

        response.raise_for_status()

        return response.json()