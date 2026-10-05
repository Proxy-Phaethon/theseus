import dns.resolver

class TeamCymruTool:
    REVERSE_ZONE = "origin.asn.cymru.com"

    def run(self, ip: str) -> dict:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{self.REVERSE_ZONE}"

        answers = dns.resolver.resolve(
            query,
            "TXT",
            lifetime=15,
        )

        results = []

        for answer in answers:
            value = answer.to_text().strip('"')
            parts = [part.strip() for part in value.split("|")]

            if len(parts) != 5:
                continue

            results.append(
                {
                    "asn": parts[0],
                    "prefix": parts[1],
                    "country": parts[2],
                    "registry": parts[3],
                    "allocated": parts[4],
                }
            )

        return {
            "ip": ip,
            "results": results,
        }