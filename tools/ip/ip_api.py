import requests

class IPAPITool:
    BASE_URL = "http://ip-api.com/json"

    FIELDS = ",".join(
        [
            "status",
            "message",
            "continent",
            "continentCode",
            "country",
            "countryCode",
            "region",
            "regionName",
            "city",
            "district",
            "zip",
            "lat",
            "lon",
            "timezone",
            "offset",
            "currency",
            "isp",
            "org",
            "as",
            "asname",
            "reverse",
            "mobile",
            "proxy",
            "hosting",
            "query",
        ]
    )

    def run(self, ip: str) -> dict:
        params = {
            "fields": self.FIELDS,
        }

        response = requests.get(
            f"{self.BASE_URL}/{ip}",
            params=params,
            timeout=15,
        )

        response.raise_for_status()

        return response.json()
