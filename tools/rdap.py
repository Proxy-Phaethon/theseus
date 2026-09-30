import requests

class RDAPTool:
    BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

    def run(self, domain):
        rdap_url = self._find_rdap_server(domain)

        response = requests.get(
            f"{rdap_url}domain/{domain}",
            headers={
                "Accept": "application/rdap+json",
            },
            timeout=10,
        )

        response.raise_for_status()

        return response.json()

    def _find_rdap_server(self, domain):
        tld = domain.rstrip(".").split(".")[-1].lower()

        response = requests.get(
            self.BOOTSTRAP_URL,
            timeout=10,
        )

        response.raise_for_status()

        bootstrap = response.json()

        for service in bootstrap["services"]:
            tlds, servers = service

            if tld in [value.lower() for value in tlds]:
                return servers[0].rstrip("/") + "/"

        raise ValueError(
            f"No RDAP server found for .{tld}"
        )