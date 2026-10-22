import re
import time
from urllib.parse import urlparse

import requests

class CertTransparencyTool:
    API_URL = "https://crt.sh/"
    TIMEOUT = 30

    def run(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required")

        hostname = parsed.hostname.lower().rstrip(".")

        # Query certificates matching the domain and its subdomains.
        domain = hostname[4:] if hostname.startswith("www.") else hostname

        start = time.perf_counter()

        response = requests.get(
            self.API_URL,
            params={
                "q": domain,
                "output": "json",
            },
            headers={
                "User-Agent": "Theseus/0.5.0",
                "Accept": "application/json",
            },
            timeout=self.TIMEOUT,
        )
        response.raise_for_status()

        raw_result = response.json()

        if not isinstance(raw_result, list):
            raise ValueError("Unexpected response from crt.sh")

        certificates = []
        hostnames = set()

        for certificate in raw_result:
            if not isinstance(certificate, dict):
                continue

            names = certificate.get("name_value", "")

            for name in names.splitlines():
                name = name.strip().lower().rstrip(".")

                if name.startswith("*."):
                    name = name[2:]

                # Keep only the queried domain and its subdomains.
                if (
                    name == domain
                    or name.endswith("." + domain)
                ) and not any(char in name for char in ("*", "/")):
                    if re.fullmatch(
                        r"[a-z0-9.-]+",
                        name,
                    ):
                        hostnames.add(name)

            certificates.append(certificate)

        return {
            "requested_url": url,
            "queried_domain": domain,
            "status": "found" if certificates else "not_found",
            "certificate_count": len(certificates),
            "hostname_count": len(hostnames),
            "hostnames": sorted(hostnames),
            "certificates": certificates,
            "elapsed_ms": round(
                (time.perf_counter() - start) * 1000
            ),
        }