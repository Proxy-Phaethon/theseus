import subprocess

class DIGTool:
    RECORD_TYPES = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
        "SRV",
        "CAA",
    ]

    def run(self, domain):
        results = {}

        for record_type in self.RECORD_TYPES:
            result = subprocess.run(
                ["dig", "+noall", "+answer", domain, record_type],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())

            results[record_type] = result.stdout.strip()

        return results