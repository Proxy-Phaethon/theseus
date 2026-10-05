import ipaddress

import requests

class X4BNetTool:
    BASE_URL = (
        "https://raw.githubusercontent.com/"
        "X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
    )

    def run(self, ip: str) -> dict:
        response = requests.get(
            self.BASE_URL,
            timeout=15,
        )
        response.raise_for_status()

        target = ipaddress.ip_address(ip)

        networks = []

        for line in response.text.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            networks.append(ipaddress.ip_network(line))

        matches = [
            str(network)
            for network in networks
            if target in network
        ]

        return {
            "ip": ip,
            "is_vpn": bool(matches),
            "matching_networks": matches,
        }