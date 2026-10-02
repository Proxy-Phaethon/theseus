import dns.resolver
from urllib.parse import urlparse

class DNSTool:
    RECORD_TYPES = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
    ]

    def run(self, url):
        hostname = urlparse(url).hostname

        if not hostname:
            raise ValueError("Invalid URL")

        results = {
            "hostname": hostname,
            "records": {},
        }

        resolver = dns.resolver.Resolver()

        for record_type in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(
                    hostname,
                    record_type,
                )

                results["records"][record_type] = [
                    answer.to_text()
                    for answer in answers
                ]

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                results["records"][record_type] = []

        return results